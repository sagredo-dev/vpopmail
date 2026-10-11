/*
 * test_extract_headers.c - tests for extract_headers() in vdelivermail.c:
 * which headers are taken, folding, first-wins, truncation, and dropping a
 * decoded header that doesn't fit.
 *
 * Links vdelivermail.c itself, compiled with -Dmain=vdelivermail_main so this
 * file's main() is the entry point, and so everything vdelivermail links.
 * "make check-headers" builds and runs it.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "config.h"   /* VALIAS */
#include "gelf.h"

/* From vdelivermail.c, which has no header declaring them. */
extern gelf_t gelf;
void extract_headers(message_headers_t *h, const char *tracking_header);
void collect_delivered_to(char ***delivered_to);
bool fgets_truncated(const char *buf, size_t size, FILE *f);
int load_text_file(const char *filename, char ***lines_out);
/* Really takes a const vqpasswd_copy_t *, which only vdelivermail.c defines. These tests pass NULL. */
int check_forward_deliver(const void *recipient);
#ifdef VALIAS
void record_valias_instructions(char **lines);
#endif
int array_count(char **lines);
void free_array(char **lines);

static int failures;
static int checks;

static char logbuf[16384];

/* Make the len bytes at msg, which may include NULs, the contents of stdin.
 * freopen()ed rather than dup2()ed: glibc's fseek() on a read stream reuses
 * its buffer when the target is inside it, so rewind_stdin() would
 * otherwise see the previous message again. */
static void set_stdin_n(const char *msg, size_t len) {
    char path[] = "/tmp/test_extract_headersXXXXXX";
    int fd = mkstemp(path);

    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    if (write(fd, msg, len) != (ssize_t)len) {
        perror("write");
        exit(2);
    }
    close(fd);
    if (freopen(path, "r", stdin) == NULL) {
        perror("freopen");
        exit(2);
    }
    unlink(path);
}

static void set_stdin(const char *msg) {
    set_stdin_n(msg, strlen(msg));
}

/* Run check_forward_deliver() in a child, in a fresh directory holding a
 * .qmail with contents (none if NULL). The child is needed because a defer
 * exits. Returns its result (-1 or 1), or the exit code if it exited.
 * *delivered, if given, reports whether a "delivered" file appeared. */
static int run_forward(const char *contents, bool *delivered) {
    char dir[] = "/tmp/test_forwardXXXXXX";
    char path[sizeof(dir) + 20];
    pid_t pid;
    int status;
    int result;

    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    if (contents != NULL) {
        FILE *f;

        snprintf(path, sizeof(path), "%s/.qmail", dir);
        f = fopen(path, "w");
        fputs(contents, f);
        fclose(f);
    }
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        if (chdir(dir) != 0 || freopen("/dev/null", "w", stdout) == NULL) {
            _exit(2);
        }
        result = check_forward_deliver(NULL);
        _exit(result == -1 ? 254 : result == 1 ? 253 : 2);
    }
    waitpid(pid, &status, 0);

    snprintf(path, sizeof(path), "%s/delivered", dir);
    if (delivered != NULL) {
        *delivered = access(path, F_OK) == 0;
    }
    unlink(path);
    snprintf(path, sizeof(path), "%s/.qmail", dir);
    unlink(path);
    rmdir(dir);

    if (!WIFEXITED(status)) {
        return -999;
    }
    switch (WEXITSTATUS(status)) {
    case 254: return -1;
    case 253: return 1;
    default:  return WEXITSTATUS(status);
    }
}

/* Run extract_headers() over the len bytes at msg, which may include NULs,
 * with the file log captured in logbuf. */
static void run_n(const char *msg, size_t len, const char *tracking_header) {
    FILE *log = tmpfile();
    ssize_t n;

    if (log == NULL) {
        perror("tmpfile");
        exit(2);
    }
    set_stdin_n(msg, len);

    /* extract_headers() logs through vdelivermail.c's global gelf. */
    memset(&gelf, 0, sizeof(gelf));
    gelf.sock = -1;
    gelf.log_fd = fileno(log);
    gelf.config.file.enabled = 1;
    gelf.config.file.min_severity = 7;
    gelf.config.file.format = GELF_FORMAT_GELF;
    snprintf(gelf.config.tracking_header, sizeof(gelf.config.tracking_header), "%s",
             tracking_header ? tracking_header : "");

    extract_headers(&gelf.context.headers, gelf.config.tracking_header);

    lseek(gelf.log_fd, 0, SEEK_SET);
    n = read(gelf.log_fd, logbuf, sizeof(logbuf) - 1);
    logbuf[n > 0 ? n : 0] = '\0';
    fclose(log);
}

static void run(const char *msg, const char *tracking_header) {
    run_n(msg, strlen(msg), tracking_header);
}

static void expect_str(const char *name, const char *got, const char *want) {
    checks++;
    if (strcmp(got, want) != 0) {
        failures++;
        printf("  FAIL  %s\n      expected [%s]\n      actual   [%s]\n", name, want, got);
    } else {
        printf("  ok    %s\n", name);
    }
}

static void expect_true(const char *name, bool ok) {
    checks++;
    if (!ok) {
        failures++;
        printf("  FAIL  %s\n", name);
        if (logbuf[0]) {
            printf("      log: %s", logbuf);
        }
    } else {
        printf("  ok    %s\n", name);
    }
}

static bool log_has(const char *needle) {
    return strstr(logbuf, needle) != NULL;
}

static bool ends_with(const char *s, const char *tail) {
    size_t n = strlen(s);
    size_t t = strlen(tail);
    return n >= t && strcmp(s + n - t, tail) == 0;
}

int main(void) {
    message_headers_t *h = &gelf.context.headers;
    char msg[8192];
    char *p;
    int i;

    printf("Taking headers\n");
    run("Received: from a by b; 27 Sep 2026 07:41:00 -0000\n"
        "MIME-Version: 1.0\n"
        "Subject: hello\n"
        " folded\n"
        "\tworld\n"
        "Date: Sun, 27 Sep 2026 15:41:00 +0800\n"
        "\n"
        "Subject: in the body, not a header\n", NULL);
    expect_str("folded lines joined with single spaces", h->subject, "hello folded world");
    expect_str("Received taken", h->received, "from a by b; 27 Sep 2026 07:41:00 -0000");
    expect_str("Date taken", h->date, "Sun, 27 Sep 2026 15:41:00 +0800");
    expect_true("nothing logged for an ordinary message", logbuf[0] == '\0');

    printf("\nFirst wins\n");
    run("Subject:\n"
        "Subject: FAKE second subject\n"
        "To: first@example.com\n"
        "TO: second@example.com\n"
        " continuation of the repeat\n"
        "\n", NULL);
    expect_str("an empty first Subject still blocks a second", h->subject, "");
    expect_str("a repeat (any case) and its continuation are ignored", h->to, "first@example.com");

    printf("\nDecoding\n");
    run("To: =?UTF-8?B?w6k=?= <e@example.com>\n"
        "Subject: =?UTF-8?Q?a?=\n"
        " =?UTF-8?Q?b?=\n"
        "Message-ID: <=?UTF-8?B?w6k=?=@example.com>\n"
        "\n", NULL);
    expect_str("To display name decoded", h->to, "\xC3\xA9 <e@example.com>");
    expect_str("encoded-words across a fold join without a space", h->subject, "ab");
    expect_str("Message-ID never decoded", h->message_id, "<=?UTF-8?B?w6k=?=@example.com>");

    printf("\nRaw 8-bit headers (RFC 6532)\n");
    run("Subject: Caf\xC3\xA9\n"
        "X-Spam-Status: No, caf\xE9\n"
        "Received: from a (\xE2\x80\xAE) by b; 27 Sep 2026 07:41:00 -0000\n"
        "\n", NULL);
    expect_str("raw UTF-8 Subject kept", h->subject, "Caf\xC3\xA9");
    expect_str("invalid byte in an undecoded header replaced", h->x_spam_status, "No, caf" "\xEF\xBF\xBD");
    expect_str("bidi override in an undecoded header replaced", h->received,
               "from a (\xEF\xBF\xBD) by b; 27 Sep 2026 07:41:00 -0000");

    printf("\nTracking header\n");
    run("X-Track: abc123\nSubject: s\n\n", "X-Track");
    expect_str("tracking header taken", h->tracking_header, "abc123");
    run("Subject: s\n\n", "Subject");
    expect_str("tracking set to a standard name: the standard field keeps it", h->subject, "s");
    expect_str("tracking set to a standard name: tracking stays empty", h->tracking_header, "");

    printf("\nToo long\n");
    p = msg;
    p += sprintf(p, "Authentication-Results: mx.example;\n");
    for (i = 0; i < 40; i++) {
        p += sprintf(p, "\tdkim=pass header.i=@example%02d.com header.s=sel;\n", i);
    }
    sprintf(p, "\n");
    run(msg, NULL);
    expect_true("undecoded field cut at its size", strlen(h->authentication_results) == HEADER_VALUE_LONG_MAX - 1);
    expect_true("undecoded field ends in \"...\"", ends_with(h->authentication_results, "..."));
    expect_true("no warning for a cut undecoded field", logbuf[0] == '\0');

    p = msg;
    p += sprintf(p, "From: ");
    for (i = 0; i < 600; i++) {
        *p++ = 'A';
    }
    sprintf(p, " <a@example.com>\n\n");
    run(msg, NULL);
    expect_str("decode field too long when read is dropped", h->from, "");
    expect_true("... and reported with the start of its value",
                log_has("From header too long to log, omitted. Undecoded, it starts: AAAA"));

    p = msg;
    p += sprintf(p, "Subject: =?UTF-8?B?");
    for (i = 0; i < 60; i++) {
        p += sprintf(p, "////");
    }
    sprintf(p, "?=\n\n");
    run(msg, NULL);
    expect_true("decode field too long once decoded is cut on a character",
                ends_with(h->subject, "...") && strlen(h->subject) < HEADER_VALUE_MAX);
    expect_true("... without a warning", logbuf[0] == '\0');

    /* Too long to store, so dropped. The sample is 79 bytes of ASCII then
     * 8-bit bytes, each sanitised to a 3-byte U+FFFD: its 80-byte limit
     * would cut the first one, so it backs off to 79. */
    p = msg;
    p += sprintf(p, "From: ");
    for (i = 0; i < 79; i++) {
        *p++ = 'x';
    }
    for (i = 0; i < 500; i++) {
        *p++ = '\xE9';
    }
    sprintf(p, "\n\n");
    run(msg, NULL);
    {
        char want[100];
        memset(want, 'x', 79);
        strcpy(want + 79, "...\"");
        expect_true("sample never splits a U+FFFD", log_has(want));
    }

    printf("\nDelivered-To collection\n");
    /* fgets() reads 1023 bytes into loop_buf. Padding "X-Pad: " (7 bytes)
     * with 1016 more puts a forged "Delivered-To:" exactly at the start of
     * the rest of that physical line, which must be discarded, not read as
     * a line of its own. */
    p = msg;
    p += sprintf(p, "Delivered-To: first@example.com\nX-Pad: ");
    for (i = 0; i < 1016; i++) {
        *p++ = 'x';
    }
    sprintf(p, "Delivered-To: fake@example.com\n"
               "Delivered-To: second@example.com\n"
               "\n"
               "Delivered-To: in the body\n");
    set_stdin(msg);
    {
        char **dt = NULL;

        collect_delivered_to(&dt);
        expect_true("padding can't forge a Delivered-To line; body not read",
                    array_count(dt) == 2
                    && strcmp(dt[0], "first@example.com") == 0
                    && strcmp(dt[1], "second@example.com") == 0);
        free_array(dt);
    }

    /* "Delivered-To:" (13 bytes), 993 spaces and the 17-byte address fill
     * loop_buf's 1023 bytes exactly, leaving the newline for the next read.
     * The line isn't cut, so the value must not be marked cut either. */
    p = msg;
    p += sprintf(p, "Delivered-To:");
    for (i = 0; i < 993; i++) {
        *p++ = ' ';
    }
    sprintf(p, "exact@example.com\n"
               "Delivered-To: next@example.com\n"
               "\n");
    set_stdin(msg);
    {
        char **dt = NULL;

        collect_delivered_to(&dt);
        expect_true("a line exactly filling loop_buf isn't cut; next line still read",
                    array_count(dt) == 2
                    && strcmp(dt[0], "exact@example.com") == 0
                    && strcmp(dt[1], "next@example.com") == 0);
        free_array(dt);
    }

    printf("\nfgets_truncated\n");
    {
        /* len is given because some inputs hold a NUL. */
        static const struct {
            const char *name;
            const char *input;
            size_t len;
            bool cut;
            const char *rest;   /* what the next fgets() should see */
        } cases[] = {
            { "short line",                   "abc\nnext\n",        9, false, "next\n" },
            { "fills buf exactly, then \\n",  "abcd\nnext\n",      10, false, "next\n" },
            { "fills buf exactly, then EOF",  "abcd",                4, false, NULL },
            { "short last line, no \\n",      "ab",                  2, false, NULL },
            { "one byte too long",            "abcde\nnext\n",     11, true,  "next\n" },
            { "much too long",                "abcdefghij\nnext\n", 16, true, "next\n" },
            { "too long, then EOF",           "abcdefghij",         10, true,  NULL },
            { "NUL mid-line doesn't swallow the next line",  "a\0b\nnext\n", 9, false, "next\n" },
            { "NUL first doesn't swallow the next line",     "\0b\nnext\n",  8, false, "next\n" },
            { "NUL in a line that's too long, still cut",     "a\0cdef\nnext\n", 12, true, "next\n" },
        };
        size_t k;

        for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            FILE *f = tmpfile();
            char buf[5];   /* holds 4 characters */
            char rest[32];
            bool cut;
            bool rest_ok;

            fwrite(cases[k].input, 1, cases[k].len, f);
            rewind(f);
            if (fgets(buf, sizeof(buf), f) == NULL) {
                expect_true(cases[k].name, false);
                fclose(f);
                continue;
            }
            cut = fgets_truncated(buf, sizeof(buf), f);
            if (cases[k].rest == NULL) {
                rest_ok = fgets(rest, sizeof(rest), f) == NULL;
            } else {
                rest_ok = fgets(rest, sizeof(rest), f) != NULL && strcmp(rest, cases[k].rest) == 0;
            }
            expect_true(cases[k].name, cut == cases[k].cut && rest_ok);
            fclose(f);
        }
    }

    printf("\nCut lines\n");
    /* line[] holds 2047 bytes. Whitespace after the colon is trimmed before
     * storing, so the part of a padded line that fit can be short enough for
     * its field: the cut must still mark the field, so the lost rest shows as
     * "..." and later continuation lines aren't appended after the gap. */
    p = msg;
    p += sprintf(p, "Message-ID:");
    for (i = 0; i < 2030; i++) {
        *p++ = ' ';
    }
    p += sprintf(p, "<abc@x>");
    for (i = 0; i < 3000; i++) {
        *p++ = 'y';
    }
    sprintf(p, "\nFrom: real@example.com\n\n");
    run(msg, NULL);
    expect_str("padded undecoded field that fits is still marked cut", h->message_id, "<abc@x...");
    expect_str("... and the next header is intact", h->from, "real@example.com");

    p = msg;
    p += sprintf(p, "Subject:");
    for (i = 0; i < 2035; i++) {
        *p++ = ' ';
    }
    p += sprintf(p, "hello");
    for (i = 0; i < 3000; i++) {
        *p++ = 'y';
    }
    sprintf(p, "\n\n");
    run(msg, NULL);
    expect_true("padded decoded field that fits is still dropped",
                h->subject[0] == '\0' && log_has("Subject header too long to log"));

    p = msg;
    p += sprintf(p, "Message-ID:");
    for (i = 0; i < 2030; i++) {
        *p++ = ' ';
    }
    p += sprintf(p, "<abc@x>");
    for (i = 0; i < 3000; i++) {
        *p++ = 'y';
    }
    sprintf(p, "\n tail\n\n");
    run(msg, NULL);
    expect_str("continuation after a cut line is ignored", h->message_id, "<abc@x...");

    /* 2047 - 2030 spaces - "mid" leaves 14 'y' in the part that fit. */
    p = msg;
    p += sprintf(p, "Message-ID: <first>\n");
    for (i = 0; i < 2030; i++) {
        *p++ = ' ';
    }
    p += sprintf(p, "mid");
    for (i = 0; i < 3000; i++) {
        *p++ = 'y';
    }
    sprintf(p, "\n tail\n\n");
    run(msg, NULL);
    expect_str("cut continuation marks the field; later continuation ignored",
               h->message_id, "<first> midyyyyyyyyyyyyyy...");

    /* The rest of a cut line must be discarded on every path, or it is read
     * as a header of its own. */
    p = msg;
    p += sprintf(p, "From: real@example.com\nFrom:");
    for (i = 0; i < 2100; i++) {
        *p++ = 'x';
    }
    sprintf(p, "Subject: forged\nSubject: real\n\n");
    run(msg, NULL);
    expect_str("cut repeated header can't forge the next header", h->subject, "real");

    p = msg;
    p += sprintf(p, "X-Pad:");
    for (i = 0; i < 2100; i++) {
        *p++ = 'x';
    }
    sprintf(p, "Subject: forged\nSubject: real\n\n");
    run(msg, NULL);
    expect_str("cut untaken header can't forge the next header", h->subject, "real");

    printf("\nNUL bytes in headers\n");
    {
        static const char nul_msg[] = "Subject: a\0b\nFrom: Bob <bob@example.com>\n\n";

        run_n(nul_msg, sizeof(nul_msg) - 1, NULL);
        expect_str("NUL in Subject keeps the text before it", h->subject, "a");
        expect_str("NUL in Subject doesn't hide the next header", h->from, "Bob <bob@example.com>");
    }
    {
        static const char nul_msg[] = "X-Pad: a\0b\nDelivered-To: dt@example.com\n\n";
        char **dt = NULL;

        set_stdin_n(nul_msg, sizeof(nul_msg) - 1);
        collect_delivered_to(&dt);
        expect_true("NUL in a header doesn't hide the next Delivered-To",
                    array_count(dt) == 1 && strcmp(dt[0], "dt@example.com") == 0);
        free_array(dt);
    }

    printf("\nload_text_file\n");
    /* 299 characters fill line[MAX_BUFF] exactly, leaving the newline for
     * the next read. That's a whole line, not a "Line is too long" defer. */
    {
        char path[] = "/tmp/test_load_text_fileXXXXXX";
        int fd = mkstemp(path);
        FILE *f = fdopen(fd, "w");
        char **lines = NULL;

        for (i = 0; i < 299; i++) {
            fputc('x', f);
        }
        fputs("\nsecond\n", f);
        fclose(f);
        expect_true("a line exactly filling the buffer loads whole; next line still read",
                    load_text_file(path, &lines) == 0
                    && array_count(lines) == 2 && strlen(lines[0]) == 299
                    && strcmp(lines[1], "second") == 0);
        free_array(lines);

        f = fopen(path, "w");
        for (i = 0; i < 300; i++) {
            fputc('x', f);
        }
        fputs("\n", f);
        fclose(f);
        lines = (char **)1;
        expect_true("a line one too long: -2, no array",
                    load_text_file(path, &lines) == -2 && lines == NULL);

        chmod(path, 0);
        lines = (char **)1;
        expect_true("unreadable: -2, no array",
                    load_text_file(path, &lines) == -2 && lines == NULL);

        unlink(path);
        lines = (char **)1;
        expect_true("absent: -1, no array",
                    load_text_file(path, &lines) == -1 && lines == NULL);
    }

    printf("\ncheck_forward_deliver\n");
    {
        char long_qmail[400];

        p = long_qmail;
        p += sprintf(p, "|touch delivered\n|");
        for (i = 0; i < 299; i++) {
            *p++ = 'x';
        }
        sprintf(p, "\n");

        expect_true("no .qmail: not handled", run_forward(NULL, NULL) == -1);
        expect_true("empty .qmail: not handled", run_forward("", NULL) == -1);
        expect_true("only comments: handled", run_forward("# nothing\n#&a@example.com\n", NULL) == 1);
        expect_true("blank first line defers", run_forward("\n# nothing\n", NULL) == 111);
        {
            bool delivered = true;

            expect_true("control: a valid line is delivered",
                        run_forward("|touch delivered\n", &delivered) == 1 && delivered);
            expect_true("a line too long: treated as absent", run_forward(long_qmail, &delivered) == -1);
            expect_true("... and the line above it isn't delivered", !delivered);
        }
    }

#ifdef VALIAS
    printf("\nvalias lines recorded for the exit log\n");
    {
        char *normal[] = { "# forward to the team", "&alice@example.org",
                           "/home/vpopmail/domains/example.com/bob/Maildir/", NULL };
        char *junk[] = { "&caf\xE9@x.org", "| /usr/bin/prog \x1B[31mred", NULL };
        char *comments[] = { "# disabled for now", "#&old@example.org", NULL };
        char *one[] = { "&only@example.org", NULL };
        static char paths[40][80];
        char *many[41];
        const char *b = gelf.context.valias_instructions;
        const char *last;
        int nl;

        record_valias_instructions(normal);
        expect_str("rows joined by newlines, comments kept, none after the last", b,
                   "# forward to the team\n&alice@example.org\n"
                   "/home/vpopmail/domains/example.com/bob/Maildir/");

        record_valias_instructions(junk);
        expect_str("each row sanitised; separators survive", b,
                   "&caf\xEF\xBF\xBD@x.org\n| /usr/bin/prog \xEF\xBF\xBD[31mred");

        record_valias_instructions(comments);
        expect_str("rows that are all comments are still recorded", b,
                   "# disabled for now\n#&old@example.org");

        record_valias_instructions(one);
        expect_str("a single row has no newline", b, "&only@example.org");

        for (i = 0; i < 40; i++) {
            snprintf(paths[i], sizeof(paths[i]),
                     "/home/vpopmail/domains/example.com.au/user%02d/Maildir/", i);
            many[i] = paths[i];
        }
        many[40] = NULL;
        record_valias_instructions(many);
        nl = 0;
        for (p = (char *)b; *p; p++) {
            nl += (*p == '\n');
        }
        last = strrchr(b, '\n') + 1;
        /* 40 rows of 53 bytes don't fit: 37 are kept whole, then a count of
         * the rest, which are the rows most likely never to have run. */
        expect_str("overflow ends with the count of rows left out", last, "... 3 more");
        expect_true("... after 37 whole rows, within the field",
                    nl == 37 && strlen(b) < sizeof(gelf.context.valias_instructions)
                    && strncmp(b, paths[0], strlen(paths[0])) == 0);
    }
#endif

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
