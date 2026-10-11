/*
 * test_headers.c - unit tests for store_header_value(),
 * sanitise_inplace() and decode_header_field() in header_text.c.
 *
 * Standalone: links only header_text.c, nmh/fmt_rfc2047.c and
 * nmh/shim/check_charset.c, so it does not drag in gelf.c's curl, cJSON
 * and inih dependencies.
 *
 *   gcc -Wall -Wextra -Werror -I. -Inmh/shim -o tests/test_headers \
 *       tests/test_headers.c header_text.c nmh/fmt_rfc2047.c \
 *       nmh/shim/check_charset.c
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "header_text.h"

#define R "\xEF\xBF\xBD"   /* U+FFFD */

static int failures;
static int checks;

static void hexdump(const char *label, const char *s) {
    size_t i;

    printf("      %-9s %2zu bytes:", label, strlen(s));
    for (i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c <= 0x7E) {
            printf(" %c", c);
        } else {
            printf(" \\x%02X", c);
        }
    }
    printf("\n");
}

/* Run a header value through the decode pipeline: store each physical line,
 * then decode the completed field. extract_headers() would drop a decode
 * field whose raw value was cut; decoding it anyway here checks that the
 * decoder copes with a cut encoded-word. */
static void run(char *field, const char *const *lines, size_t nlines) {
    size_t i;

    field[0] = '\0';
    for (i = 0; i < nlines; i++) {
        if (store_header_value(field, HEADER_VALUE_MAX, lines[i])) {
            break;
        }
    }
    decode_header_field(field, HEADER_VALUE_MAX, NULL, NULL);   /* NULL reports allowed */
}

static void expect(const char *name, const char *input, const char *want) {
    char field[HEADER_VALUE_MAX];
    const char *lines[1];

    lines[0] = input;
    run(field, lines, 1);

    checks++;
    if (strcmp(field, want) != 0) {
        failures++;
        printf("  FAIL  %s\n", name);
        printf("      input     %s\n", input);
        hexdump("expected", want);
        hexdump("actual", field);
    } else {
        printf("  ok    %s\n", name);
    }
}

/* Minimal UTF-8 well-formedness check, independent of header_text.c's, so a
 * bug in the sanitiser cannot mask itself. Table 3-7. */
static int valid_utf8(const char *s) {
    const unsigned char *p = (const unsigned char *)s;

    while (*p) {
        unsigned char lo = 0x80, hi = 0xBF;
        int need, i;

        if (*p <= 0x7F)                      { p++; continue; }
        else if (*p >= 0xC2 && *p <= 0xDF)   need = 1;
        else if (*p == 0xE0)                 { need = 2; lo = 0xA0; }
        else if (*p >= 0xE1 && *p <= 0xEC)   need = 2;
        else if (*p == 0xED)                 { need = 2; hi = 0x9F; }
        else if (*p >= 0xEE && *p <= 0xEF)   need = 2;
        else if (*p == 0xF0)                 { need = 3; lo = 0x90; }
        else if (*p >= 0xF1 && *p <= 0xF3)   need = 3;
        else if (*p == 0xF4)                 { need = 3; hi = 0x8F; }
        else return 0;

        p++;
        for (i = 0; i < need; i++, p++) {
            unsigned char clo = (i == 0) ? lo : 0x80;
            unsigned char chi = (i == 0) ? hi : 0xBF;
            if (*p < clo || *p > chi) return 0;
        }
    }
    return 1;
}

static void expect_property(const char *name, const char *input) {
    char field[HEADER_VALUE_MAX];
    const char *lines[1];

    lines[0] = input;
    run(field, lines, 1);

    checks++;
    if (!valid_utf8(field) || strlen(field) >= HEADER_VALUE_MAX) {
        failures++;
        printf("  FAIL  %s (valid_utf8=%d len=%zu)\n",
               name, valid_utf8(field), strlen(field));
        hexdump("actual", field);
    } else {
        printf("  ok    %s (len=%zu, valid UTF-8, NUL-terminated)\n",
               name, strlen(field));
    }
}

/* Run physical lines through the undecoded pipeline, as extract_headers()
 * does for fields it doesn't decode: store until input is lost, then
 * sanitise. A deliberately small field lets the "..." be checked exactly.
 * want_repaired and want_truncated are sanitise_inplace()'s two reports. */
static void expect_sized(const char *name, size_t size,
                         const char *const *lines, size_t nlines,
                         const char *want, bool want_repaired, bool want_truncated) {
    char field[64];
    bool lost = false;
    bool repaired;
    bool truncated;
    size_t i;

    field[0] = '\0';
    for (i = 0; i < nlines && !lost; i++) {
        lost = store_header_value(field, size, lines[i]);
    }
    sanitise_inplace(field, size, lost, &repaired, &truncated);

    checks++;
    if (strcmp(field, want) != 0 || strlen(field) >= size || !valid_utf8(field)
        || repaired != want_repaired || truncated != want_truncated) {
        failures++;
        printf("  FAIL  %s (repaired %d want %d, truncated %d want %d)\n", name,
               repaired, want_repaired, truncated, want_truncated);
        hexdump("expected", want);
        hexdump("actual", field);
    } else {
        printf("  ok    %s\n", name);
    }
}

/* Decode input as a From or Sender value, then extract its address. want is the
 * address, or "" if extraction should fail. */
static void expect_address(const char *name, const char *input, const char *want) {
    char field[HEADER_VALUE_MAX];
    char addr[HEADER_VALUE_MAX];
    const char *lines[1];
    bool ok;

    lines[0] = input;
    run(field, lines, 1);
    ok = extract_address(field, addr, sizeof(addr));

    checks++;
    if (ok != (want[0] != '\0') || strcmp(addr, want) != 0) {
        failures++;
        printf("  FAIL  %s\n", name);
        printf("      input     %s\n", input);
        hexdump("expected", want);
        hexdump("actual", addr);
    } else {
        printf("  ok    %s\n", name);
    }
}

int main(void) {
    char field[HEADER_VALUE_MAX];
    char big[1400];
    char b64[1400];   /* "=?UTF-8?B?" + 400*3 + "?=" + NUL = 1213 */
    size_t i;

    printf("RFC 2047 decoding\n");
    expect("base64 UTF-8",            "=?UTF-8?B?w6k=?=",            "\xC3\xA9");
    expect("Q-encoding, lowercase charset", "=?utf-8?Q?caf=C3=A9?=",  "caf\xC3\xA9");
    expect("Q underscore is space",   "=?UTF-8?Q?a_b?=",             "a b");

    printf("\nMalformed UTF-8 inside an encoded-word\n");
    expect("0xFF",                    "=?UTF-8?B?/w==?=",            R);
    expect("overlong C0 80",          "=?UTF-8?B?wIA=?=",            R R);
    expect("surrogate ED A0 80",      "=?UTF-8?B?7aCA?=",            R R R);
    expect("embedded NUL",            "=?UTF-8?B?YQBi?=",            "a" R "b");
    expect("Q-encoded NUL dropped (accepted, but undesirable decode behaviour)",
           "=?UTF-8?Q?a=00b?=",           "ab");
    expect("malformed = in Q dropped (accepted, but undesirable decode behaviour)",
           "=?UTF-8?Q?a=ZZb?=",           "aZZb");

    printf("\nText between encoded-words\n");
    expect("non-space text kept",     "=?UTF-8?Q?a?= = =?UTF-8?Q?b?=", "a = b");
    expect("CR is not whitespace",    "=?UTF-8?Q?a?=\r =?UTF-8?Q?b?=", "a" R " b");

    printf("\nWell-formed but rejected code points\n");
    expect("U+202E bidi override",    "=?UTF-8?B?4oCu?=",            R);
    expect("U+200B zero-width",       "=?UTF-8?B?4oCLYQ==?=",        R "a");
    expect("tab becomes space",       "=?UTF-8?Q?a=09b?=",           "a b");
    expect("U+2060 word joiner, raw", "a\xE2\x81\xA0" "b",            "a" R "b");
    expect("U+061C Arabic letter mark, raw", "a\xD8\x9C" "b",          "a" R "b");
    expect("U+00AD soft hyphen, raw", "a\xC2\xAD" "b",                 "a" R "b");
    expect("TAG U+E0041 via Q",       "=?UTF-8?Q?pay=F3=A0=81=81me?=", "pay" R "me");
    expect("U+E007F cancel tag, raw", "a\xF3\xA0\x81\xBF" "b",       "a" R "b");
    expect("U+206F deprecated format, raw", "a\xE2\x81\xAF" "b",      "a" R "b");
    expect("U+FFFB annotation, raw",  "a\xEF\xBF\xBB" "b",            "a" R "b");
    expect("U+FE0F variation selector kept (emoji)",
           "\xE2\x9D\xA4\xEF\xB8\x8F",                             "\xE2\x9D\xA4\xEF\xB8\x8F");
    expect("U+2065 unassigned, between ranges, kept", "a\xE2\x81\xA5" "b", "a\xE2\x81\xA5" "b");

    printf("\nAdjacent encoded-words\n");
    expect("whitespace between dropped",
           "=?UTF-8?B?w6k=?= =?UTF-8?B?w6k=?=", "\xC3\xA9\xC3\xA9");
    expect("text between preserved",
           "=?UTF-8?B?w6k=?= x =?UTF-8?B?w6k=?=", "\xC3\xA9 x \xC3\xA9");

    printf("\nCharsets we do not decode\n");
    expect("ISO-8859-1 left raw",     "=?ISO-8859-1?Q?caf=E9?=",     "=?ISO-8859-1?Q?caf=E9?=");
    expect("RFC 2231 language tag",   "=?UTF-8*en?B?w6k=?=",         "\xC3\xA9");
    expect("unknown encoding X",      "=?UTF-8?X?abc?=",             "=?UTF-8?X?abc?=");

    printf("\nDegenerate input\n");
    /* "?\?=" avoids the ??= trigraph; the string value is "=?UTF-8?B??=". */
    expect("empty encoded text",      "=?UTF-8?B?\?=",               "");
    expect("no terminator",           "=?UTF-8?B?w6k",               "=?UTF-8?B?w6k");
    expect("bare equals",             "a=b",                         "a=b");
    expect("trailing equals",         "a=",                          "a=");
    /* Decodes to a complete, valid encoded-word. It must appear literally:
     * one decoding pass only, never a second over our own output.
     * (The plan's base64 encoded "=?UTF-8?B?w6k?==" rather than the
     * "=?UTF-8?B?w6k=?=" it gave as expected; corrected here so the
     * decoded text really is a well-formed encoded-word.) */
    expect("no second decode pass",
           "=?UTF-8?B?PT9VVEYtOD9CP3c2az0/PQ==?=", "=?UTF-8?B?w6k=?=");

    printf("\nFolding\n");
    {
        const char *lines[2];
        lines[0] = "=?UTF-8?B?w6k=?=";
        lines[1] = "\t=?UTF-8?B?w6k=?=";
        run(field, lines, 2);
        checks++;
        if (strcmp(field, "\xC3\xA9\xC3\xA9") != 0) {
            failures++;
            printf("  FAIL  two encoded-words on folded lines\n");
            hexdump("expected", "\xC3\xA9\xC3\xA9");
            hexdump("actual", field);
        } else {
            printf("  ok    two encoded-words on folded lines\n");
        }
    }

    printf("\nTruncation\n");
    memset(big, 'A', 500);
    strcpy(big + 500, "=?UTF-8?B?w6k=?= tail");
    expect_property("512-byte cut lands inside an encoded-word", big);

    strcpy(b64, "=?UTF-8?B?");
    for (i = 0; i < 400; i++) {
        strcat(b64, "w6k");   /* base64 alphabet; length forces truncation */
    }
    strcat(b64, "?=");
    expect_property("400 multi-byte chars, truncated", b64);

    printf("\nRaw 8-bit bytes fed to the decoder\n");
    /* store_header_value() keeps raw bytes, so decode_rfc2047() sees 8-bit
     * input. It must cope: high bytes outside an encoded-word are copied
     * through (and sanitised afterwards), and inside one they are simply not
     * base64/hex digits. */
    expect("8-bit byte beside an encoded-word",
           "caf\xE9 =?UTF-8?B?w6k=?=", "caf" R " \xC3\xA9");
    expect_property("8-bit byte inside the base64 payload",
                    "=?UTF-8?B?w6\xE9k=?=");
    expect_property("8-bit byte inside the charset name",
                    "=?UTF-8\xE9?B?w6k=?=");
    expect_property("8-bit byte inside a Q-encoded payload",
                    "=?UTF-8?Q?caf=C3\xE9=A9?=");
    /* Raw bytes are only sanitised once, after decoding, so a raw UTF-8
     * U+FFFD is one well-formed character like any other. */
    expect("raw U+FFFD passes through as one character",
           "\xEF\xBF\xBD plain", R " plain");
    expect("raw UTF-8 beside an encoded-word",
           "caf\xC3\xA9 =?UTF-8?B?w6k=?=", "caf\xC3\xA9 \xC3\xA9");
    expect("raw bidi override rejected",
           "a\xE2\x80\xAE" "b", "a" R "b");
    /* No "=?" means nothing to decode, but the raw bytes still need
     * sanitising: a control character must not reach the log. */
    expect("raw control, no encoded-word", "a\x01" "b", "a" R "b");
    expect("U+FFFD decoded from an encoded-word passes through",
           "=?UTF-8?B?77+9?=", R);

    printf("\nUndecoded fields: store, then sanitise (field of 12 bytes)\n");
    /* 11 bytes of content fit. With "...", 8 bytes of content remain. */
    {
        const char *fits[]      = { "12345678901" };
        const char *over[]      = { "123456789012" };
        const char *fold_full[] = { "12345678901", "more" };
        const char *fold_cut[]  = { "1234", "567890123" };
        const char *after_cut[] = { "123456789012", "more", "and more" };
        const char *utf8[]      = { "Caf\xC3\xA9" };
        const char *latin1[]    = { "caf\xE9" };
        const char *bidi[]      = { "a\xE2\x80\xAE" "b" };
        const char *wide[]      = { "123456789\xE9" };
        const char *wide_fits[] = { "12345678\xE9" };
        const char *crlf[]      = { "12345678901\r\n" };
        const char *dots[]      = { "Wait for..." };

        expect_sized("exactly fits, no marker", 12, fits, 1, "12345678901", false, false);
        expect_sized("one byte over", 12, over, 1, "12345678...", false, true);
        expect_sized("full field, then a continuation", 12, fold_full, 2, "12345678...", false, true);
        expect_sized("cut inside a continuation", 12, fold_cut, 2, "1234 567...", false, true);
        expect_sized("continuations after a cut are ignored", 12, after_cut, 3, "12345678...", false, true);
        expect_sized("raw UTF-8 kept", 12, utf8, 1, "Caf\xC3\xA9", false, false);
        expect_sized("invalid byte becomes a replacement", 12, latin1, 1, "caf" R, true, false);
        expect_sized("bidi override becomes a replacement", 12, bidi, 1, "a" R "b", true, false);
        expect_sized("replacement that won't fit is not split", 12, wide, 1, "12345678...", true, true);
        expect_sized("replacement that just fits", 12, wide_fits, 1, "12345678" R, true, false);
        expect_sized("trailing CRLF is not lost input", 12, crlf, 1, "12345678901", false, false);
        expect_sized("a value that really ends in \"...\" is not truncated",
                     12, dots, 1, "Wait for...", false, false);
    }

    printf("\nStage 1 keeps raw bytes\n");
    {
        char raw[16];

        /* Capacity 11: the cut would fall between C3 and A9, so it moves
         * before the C3 rather than store half a character. */
        raw[0] = '\0';
        checks++;
        if (!store_header_value(raw, 12, "1234567890\xC3\xA9")
            || strcmp(raw, "1234567890") != 0) {
            failures++;
            printf("  FAIL  raw cut never splits a UTF-8 character\n");
            hexdump("actual", raw);
        } else {
            printf("  ok    raw cut never splits a UTF-8 character\n");
        }

        raw[0] = '\0';
        checks++;
        if (store_header_value(raw, 12, "a\xE9\x01z")
            || strcmp(raw, "a\xE9\x01z") != 0) {
            failures++;
            printf("  FAIL  bytes stored exactly as they arrived\n");
            hexdump("actual", raw);
        } else {
            printf("  ok    bytes stored exactly as they arrived\n");
        }
    }

    printf("\nSize preconditions\n");
    {
        const char *any[] = { "abc" };
        char tiny[8] = "keep";
        char rawtiny[8] = "a\xE9";
        char big_buf[64];

        /* Below 5 bytes there is no room for one byte plus "...": the field
         * must be left exactly as it was, not written past its end. */
        checks++;
        if (!store_header_value(tiny, 4, any[0]) || strcmp(tiny, "keep") != 0) {
            failures++;
            printf("  FAIL  size 4 reports lost input, field untouched\n");
            hexdump("actual", tiny);
        } else {
            printf("  ok    size 4 reports lost input, field untouched\n");
        }

        /* Too small to sanitise into: raw bytes must not be left behind. */
        checks++;
        {
        bool truncated = false;
        sanitise_inplace(rawtiny, 4, false, NULL, &truncated);
        if (!truncated || rawtiny[0] != '\0') {
            failures++;
            printf("  FAIL  size 4 sanitise leaves no raw bytes\n");
            hexdump("actual", rawtiny);
        } else {
            printf("  ok    size 4 sanitise leaves no raw bytes\n");
        }
        }

        /* Decoded text that won't fit is cut on a character and marked,
         * and nothing is written past size: four e-acutes (8 bytes) plus
         * NUL need 9, so two fit beside "...". Bytes from 8 on must still
         * hold the input. */
        {
        static const char enc[] = "=?UTF-8?B?w6nDqcOpw6k=?=";
        bool repaired, truncated;
        memcpy(big_buf, enc, sizeof(enc));
        decode_header_field(big_buf, 8, &repaired, &truncated);
        checks++;
        if (!truncated || repaired || strcmp(big_buf, "\xC3\xA9\xC3\xA9...") != 0
            || memcmp(big_buf + 8, enc + 8, sizeof(enc) - 8) != 0) {
            failures++;
            printf("  FAIL  decode too big for size is cut on a character, no overrun\n");
            hexdump("actual", big_buf);
        } else {
            printf("  ok    decode too big for size is cut on a character, no overrun\n");
        }
        }

        /* Just fits: three e-acutes (6 bytes) + NUL in size 8. */
        {
        static const char enc3[] = "=?UTF-8?B?w6nDqcOp?=";
        bool repaired, truncated;
        memcpy(big_buf, enc3, sizeof(enc3));
        decode_header_field(big_buf, 8, &repaired, &truncated);
        checks++;
        if (truncated || repaired
            || strcmp(big_buf, "\xC3\xA9\xC3\xA9\xC3\xA9") != 0) {
            failures++;
            printf("  FAIL  decode that fits reports neither\n");
            hexdump("actual", big_buf);
        } else {
            printf("  ok    decode that fits reports neither\n");
        }
        }

        /* Junk bytes grow 3x when replaced: 12 base64 chars decode to
         * 9 bytes of 0xFF, i.e. 27 bytes of U+FFFD. In 16, four fit
         * beside "...". */
        {
        static const char junk[] = "=?UTF-8?B?////////////?=";
        bool repaired, truncated;
        memcpy(big_buf, junk, sizeof(junk));
        decode_header_field(big_buf, 16, &repaired, &truncated);
        checks++;
        if (!truncated || !repaired
            || strcmp(big_buf, R R R R "...") != 0) {
            failures++;
            printf("  FAIL  junk that grows past size is repaired, cut and marked\n");
            hexdump("actual", big_buf);
        } else {
            printf("  ok    junk that grows past size is repaired, cut and marked\n");
        }
        }
    }

    printf("\nRaw headers through the decode pipeline\n");
    expect("raw 8-bit header",        "caf\xE9",                     "caf" R);
    expect("raw UTF-8 header (RFC 6532)", "Caf\xC3\xA9 \xE2\x9C\x93", "Caf\xC3\xA9 \xE2\x9C\x93");
    expect("structured field untouched (not decoded)",
           "Wed, 16 Jul 2026 17:34:00 +0800", "Wed, 16 Jul 2026 17:34:00 +0800");

    printf("\nAddress extraction\n");
    expect_address("display name",            "John Smith <j@x.com>",          "j@x.com");
    expect_address("quoted name with comma",  "\"Smith, John\" <j@x.com>",    "j@x.com");
    expect_address("escaped quotes in name",
                "\"Bobo \\\"The Cat\\\" Carlson\" <asdsa@sadasd.example.com>",
                "asdsa@sadasd.example.com");
    expect_address("angle brackets only",     "<j@x.com>",                     "j@x.com");
    expect_address("bare address",            "j@x.com",                       "j@x.com");
    expect_address("trailing space after >",  "N <a@x>  ",                     "a@x");
    expect_address("encoded name",            "=?UTF-8?B?Wm/Fvmll?= <j@x.com>", "j@x.com");
    expect_address("encoded name with comma (Outlook)",
                "=?UTF-8?Q?M=C3=BCller=2C_Hans?= <h@x.de>",              "h@x.de");
    expect_address("comment in name",         "John (Sales) <j@x.com>",        "j@x.com");
    expect_address("first of two, bare then angle", "a@x, B <b@y>",          "b@y");
    expect_address("bare then encoded angle", "a@x =?UTF-8?Q?=3Cb@y=3E?=",    "b@y");
    expect_address("whole value one encoded-word, Q NUL dropped (accepted, but undesirable decode behaviour)",
                "=?UTF-8?Q?admin=00@evil.example?=",                     "admin@evil.example");
    expect_address("encoded < in name",
                "=?UTF-8?Q?=3Cceo@bank.com=3E?= <a@evil>",               "");
    expect_address("encoded > after address",
                "<a@evil> =?UTF-8?Q?=3Cceo@bank.com=3E?=",              "");
    expect_address("quoted name containing <", "\"<ceo@bank>\" <a@evil>",   "");
    expect_address("comment after address",   "<a@x> (<ceo@bank>)",           "");
    expect_address("bare address with comment", "a@x (Name)",                 "");
    expect_address("group",                   "g: <a@x>;",                     "");
    expect_address("empty group",             "undisclosed:;",                 "");
    expect_address("obs-route",               "<@r:a@x>",                      "");
    expect_address("quoted local part",       "\"john doe\"@x",               "");
    expect_address("domain literal",          "u@[1.2.3.4]",                   "");
    expect_address("two angle mailboxes",     "A <a@x>, B <b@y>",              "");
    expect_address("U+FFFD in address",       "a\x80" "b@x",                   "");
    expect_address("bare address cut short",  "a@exam...",                     "");
    expect_address("angle form cut short",    "N <a@x>...",                    "");
    expect_address("no @",                    "N <a>",                         "");
    expect_address("empty",                   "",                              "");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
