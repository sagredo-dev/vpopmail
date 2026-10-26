/*
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
 *
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

/* code review/cleanup/rewrite October 2004 through March, 2005
 * by Tom Collins <tom@tomlogic.com>
 *
 */

/* include files */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "maildirquota.h"
#include "vauth.h"
#include "vpopmail.h"
#include "vlimits.h"
#include "gelf.h"
#include "vdelivermail.h"
#include <ctype.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DOMAINS_TREE VPOPMAILDIR "/" DOMAINS_DIR // where vadddomain puts domains by default

/* Globals */
#define AUTH_SIZE 300

// A quota string, from the db or from a maildirsize file's first line.
// pw_shell holds the db's and is VARCHAR(MAX_PW_QUOTA) (vpopmail.h), but a maildirsize first
// line is format_maildirquota() output, which expands K/M and so can be longer: e.g.
// "100000M,1000000C" (16) is written as "104857600000S,1000000C" (22). The longest it can
// produce is "<20 digits>S,<20 digits>C", 43 bytes.
#define MAILDIR_QUOTA_SIZE 64

char TheUser[AUTH_SIZE];
char TheDomain[AUTH_SIZE];
char TheDomainDir[AUTH_SIZE];
uid_t TheDomainUid;
gid_t TheDomainGid;
char CurrentDir[AUTH_SIZE];

/* TheUser@TheDomain after vget_assign() has replaced an alias domain with the
 * real one. Every Delivered-To line we write, and the loop check in main(),
 * use this string: loop detection only works if we emit the same spelling a
 * later delivery will search for.
 *
 * This is the envelope identity. It is not always the account the mail is
 * delivered into: under QMAIL_EXT, jsmith-work@ with no such account falls
 * back to the jsmith@ user record, leaving this as jsmith-work@.
 * recipient.name@recipient.domain (the vqpasswd_copy_t in main() and
 * process_valias()) is the policy identity:
 * it names the mailbox owner whose quota, flags and SpamAssassin preferences
 * apply. Don't use this string for policy.
 */
char DealiasedRecipient[AUTH_SIZE];

/* EXT@HOST as we received it, before vget_assign(). Emitted as X-Original-To
 * when it differs, which is what Postfix's local(8) does with the same value. */
char OriginalRecipient[AUTH_SIZE];

char OriginalDomain[AUTH_SIZE];

/* Envelope sender parsed from qmail-local's RPLINE, without the surrounding
   angle brackets. Empty string means the null sender. */
#define RETURN_PATH_SIZE 512
char ReturnPath[RETURN_PATH_SIZE] = "";

int DeprecationWarning = 0;

/* Local extra_headers buffers passed to fdcopy / deliver_to_maildir. Sized so
 * Return-Path + Delivered-To + X-Original-To cannot silently truncate: a
 * mangled Delivered-To would disable loop detection for the message. */
#define HEADERS_SIZE 2048
ssize_t message_size = 0;
char bounce[AUTH_SIZE] = "delete";
int CurrentQuotaSizeFd;

#ifdef QMAIL_EXT
/* the User with '-' and following chars out if any */
char TheUserExt[AUTH_SIZE];
char TheExt[AUTH_SIZE];
#endif


int DeliverToStdout = 0;
int Verbose = 0;
const char DefaultDeliveryFile[] = VPOPMAILDIR "/etc/vdefaultdelivery";
gelf_t gelf;

#define MSG_BUF_SIZE 5000
char msgbuf[MSG_BUF_SIZE];

/* RFC 5424 / GELF severity. Same numbers as syslog(3), without <syslog.h>. The short names mimic log4j. */
#define DEBUG 7
#define INFO  6
#define WARN  4
#define ERROR 3


/* A vexiterr() that has been formatted but not yet acted upon. Strings are
 * copied, not referenced, so the struct may outlive the caller's buffers.
 */
typedef struct {
  int exit_code;          /* 0 when nothing is pending */
  int severity;           /* severity to log the exit event at */
  bool has_message;      /* false: print nothing to stdout. Distinguishes empty string from NULL */
  char message[1024];    /* generic-message substitution already applied */
  bool has_log;          /* false: emit no exit event */
  char logmsg[1024];     /* $M expanded and varargs already applied */
} pending_exit_t;


/* A header that extract_headers() has taken from this message. take_header()
 * allocates one the first time the header's name matches, and
 * extract_headers() links it into its list; being in the list is what marks
 * the header as seen, so later copies are ignored. */
struct header_field {
  const char *name;    /* including the colon, e.g. "Subject:" */
  char *value;         /* storage, e.g. h->subject */
  size_t size;         /* sizeof that storage */
  bool decode;         /* RFC 2047-decoded; dropped rather than decoded if truncated */
  bool truncated;      /* input was lost; later continuation lines are ignored */
  struct header_field *next;
};


/* Outputs of calc_maildir_constraints() */
typedef struct {
  char summary[HEADER_VALUE_MAX];
  char quota_root[PATH_MAX];
  char quota[MAILDIR_QUOTA_SIZE];
  char quota_allocation_source[40];
  char spamc_user[AUTH_SIZE];
  gid_t effective_flags;
  char domain[AUTH_SIZE];
  char overquota_bounce_template_dir[PATH_MAX];
  char domain_quota_warning_template_dir[PATH_MAX];
  char quota_warning_user[AUTH_SIZE];

  char subfolder[PATH_MAX];       // Maildir++ folder as on disk, e.g. ".Lists.Work"; empty for the inbox
  bool is_own_maildir;               // CASE 1
  bool in_main_domains_tree;
  char inferred_user[AUTH_SIZE];  // from maildir_to_email(); empty if not called, or it failed
  bool users_cdb_checked;
  bool domain_found_in_users_cdb;        // only meaningful when users_cdb_checked
  char domain_dir[PATH_MAX];      // from users/cdb
  bool within_domain_dir_checked;
  bool within_domain_dir;         // only meaningful when within_domain_dir_checked
  bool db_checked;
  bool found_in_db;               // only meaningful when db_checked
  char homedir[PATH_MAX];         // pw_dir of the account found in the db
  bool within_owner_maildir_checked;
  bool within_owner_maildir;      // only meaningful when within_owner_maildir_checked
  char maildir_owner[AUTH_SIZE];  // name@domain of the account the maildir is confirmed to belong to; empty if unknown
} maildir_constraints_t;


// Container for a user record obtained from vauth_getpw.
// We make a deep-copy, as every call to vauth_getpw returns the same pointer address,
// and the memory it references is overwritten with each call.
// Only the fields vdelivermail uses are kept: no password, cleartext password or gecos.
typedef struct {
  gid_t pw_gid;        // a bitmask containing user-specific permissions/limits
  char name[MAX_PW_NAME + 1];
  char domain[MAX_PW_DOMAIN + 1];  // the lookup key alongside name; struct vqpasswd has no domain field
  char dir[MAX_PW_DIR + 1];
  char quota_allocation_string[MAX_PW_QUOTA + 1];  // pw_shell: vpopmail keeps the quota there
} vqpasswd_copy_t;


// These log lines are intended for log files, not for mail recipients.
// If we printed them to stderr or stdout, they could end up in user-facing bounce messages.
// severity: 7=debug, 6=info, 5=notice, 4=warning, 3=error, ...
__attribute__((format(printf, 2, 3)))
void log_event(int severity, const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt); // va_start is a macro. fmt is the last fixed arg before ...
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  gelf_log(&gelf, severity, buf, NULL);
}

/* Use this fn instead of snprintf() in situations where silent truncation is acceptable.
 * This will prevent compile-time warnings for those cases. */
__attribute__((format(printf, 3, 4)))
void format_log_text(char *buf, size_t size, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, size, fmt, ap);
  va_end(ap);
}

// Like log_event, with a full_message the caller has already formatted, e.g. with snprintf().
__attribute__((format(printf, 3, 4)))
void log_detailed_event(int severity, const char *full_message, const char *short_fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, short_fmt); // va_start is a macro. short_fmt is the last fixed arg before ...
  vsnprintf(buf, sizeof(buf), short_fmt, ap);
  va_end(ap);

  gelf_log(&gelf, severity, buf, full_message);
}


/* Print an error and log it, then vexit().
 *
 * vexiterr_pend() is for callers that must not exit yet: it only formats, into
 * a pending_exit_t, and nothing is printed, logged or exited until the caller
 * runs vexiterr_report() followed by vexit(). Use it when something must be
 * logged first, e.g. log_process_start(), or when stdin must be drained before
 * the exit code becomes visible to whoever is piping the message in. Reach
 * vexit() without a further vexiterr()/log_exit(), or the run emits two exit
 * events.
 *
 * p - the pending_exit_t struct to fill in.
 *
 * See vexiterr for documentation on other inputs.
 */
__attribute__((format(printf, 5, 0)))
static void vexiterr_pend_v(pending_exit_t *p, int exit_code, int severity,
                            const char *message, const char *fmt, va_list ap) {
  char newfmt[2048];

  memset(p, 0, sizeof *p);
  p->exit_code = exit_code;
  p->severity = severity;

  if (message != NULL && message[0] == '\0') {
    if (exit_code == EXIT_DEFER)
      message = STANDARD_DEFER_MESSAGE;
    else if (exit_code == EXIT_BOUNCE)
      message = STANDARD_BOUNCE_MESSAGE;
  }

  // message==NULL means we print nothing to stdout.
  p->has_message = (message != NULL);
  if (message) snprintf(p->message, sizeof p->message, "%s", message);

  // Build log string: expand $M to message in fmt, then apply varargs.
  p->has_log = (fmt != NULL);
  if (fmt) {
    const char *src = fmt;
    char *dst = newfmt;
    char *dstend = newfmt + sizeof(newfmt) - 1;

    while (*src && dst < dstend) {
      if (src[0] == '$' && src[1] == 'M') { // not a printf conversion, so format checking ignores it
        // Inline message, escaping '%' so vsnprintf won't misread it.
        const char *m = message ? message : "";
        while (*m && dst < dstend) {
          if (*m == '%') {
            *dst++ = '%';
            if (dst < dstend) *dst++ = '%';
          } else {
            *dst++ = *m;
          }
          m++;
        }
        src += 2;
      } else {
        *dst++ = *src++;
      }
    }
    *dst = '\0';

    vsnprintf(p->logmsg, sizeof p->logmsg, newfmt, ap);
  }
}


/* Act on a prepared pending_exit_t: stdout text, then the exit event. */
static void vexiterr_report(const pending_exit_t *p) {
  size_t n;
  bool is_success = p->exit_code == EXIT_OK || p->exit_code == 99;

  // Log an unfinished delivery. Always the shared record: this runs on the way out, and a
  // nested delivery with a record of its own (deliver_quota_warning) is not the one that
  // matters here -- the outer delivery is the one still in progress.
  if (gelf.context.delivery.in_progress) {
    log_delivery(&gelf, &gelf.context.delivery);
  }

  // Print plain message to stdout; qmail reads this for bounce/defer text.
  if (p->has_message) {
    n = strlen(p->message);
    if (n > 0) {
      if (p->message[n - 1] == '\n') {
        printf("%s", p->message);
      } else {
        printf("%s\n", p->message);
      }
    }
  }

  if (p->has_log) {
    log_exit(&gelf,p->exit_code,is_success,p->severity,p->has_message ? p->message : "",p->logmsg);
  }
}


/* Format only. Returns exit_code, so a caller can write
 * "return vexiterr_pend(&pending, EXIT_BOUNCE, ERROR, ...);" and hand the code upwards.
 */
__attribute__((format(printf, 5, 6)))
int vexiterr_pend(pending_exit_t *p, int exit_code, int severity, const char *message, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vexiterr_pend_v(p, exit_code, severity, message, fmt, ap);
  va_end(ap);

  return exit_code;
}


/*
 * message  - plain string printed to stdout (qmail reads this for bounce/defer
 *            text); no format specifiers, printed as-is. An empty string
 *            with EXIT_DEFER / EXIT_BOUNCE is replaced by a generic
 *            qmail-style line (STANDARD_DEFER_MESSAGE / STANDARD_BOUNCE_MESSAGE,
 *            gelf.h) so the sender is not given internals. Deliberately short
 *            and distinct from qmail-send's own wrapper text ("I'm afraid I
 *            wasn't able to deliver your message..."), which already wraps
 *            whatever this prints -- restating it here would just be an echo.
 *            Put the real reason in fmt; $M expands to whatever was emitted.
 * fmt      - printf-style format string for the log entry. Use $M anywhere in
 *            fmt to insert the value of message. Other specifiers (%s, %d …)
 *            are filled from the varargs.  Pass "$M" when the log entry should
 *            just be the message itself.
 * ...      - arguments for %s, %d etc. in fmt (NOT for $M).
 *
 * Example:
 *   vexiterr(EXIT_BOUNCE, ERROR, "no such user", "$M: user=%s", username);
 *   // stdout → "no such user"   log → "no such user: user=alice"
 *   vexiterr(EXIT_DEFER, ERROR, "", "chdir failed: path=%s", path);
 *   // stdout → STANDARD_DEFER_MESSAGE
 *   // log    → "chdir failed: path=/var/vpopmail/domains/example.com"
 */
__attribute__((format(printf, 4, 5), noreturn))
void vexiterr(int exit_code, int severity, const char *message, const char *fmt, ...) {
  pending_exit_t pending;
  va_list ap;

  va_start(ap, fmt);
  vexiterr_pend_v(&pending, exit_code, severity, message, fmt, ap);
  va_end(ap);

  vexiterr_report(&pending);
  vexit(exit_code);
}


void Fchdir(int fd) {
  if (fchdir(fd) == -1) {
    int saved = errno;
    vexiterr(EXIT_DEFER, ERROR, "", "fchdir failed: %s",strerror(saved));
  }
}


/* Seek stdin to 0 via the FILE*, so the next fgets or read(0) both start
 * at the beginning. Defers if stdin is not seekable. */
void rewind_stdin(void) {
  if (fseek(stdin, 0L, SEEK_SET) != 0) {
    int saved = errno;
    vexiterr(EXIT_DEFER, ERROR, "", "fseek error rewinding stdin: %s", strerror(saved));
  }
  clearerr(stdin);

  /* fseek() only guarantees stdio's own view of the position; when the
   * target offset is already inside stdio's read buffer (as it is here
   * after collect_delivered_to()/extract_headers() have fgets()-buffered the whole
   * message), glibc skips the underlying lseek() entirely. That leaves the
   * kernel fd position wherever the last real read(2) left it -- e.g. at
   * EOF once a small message has been fully buffered. fdcopy() reads the
   * message with a raw read(read_fd, ...), bypassing stdio's buffer, so it
   * needs the real fd position synced too, or it reads nothing. */
  if (lseek(fileno(stdin), 0L, SEEK_SET) == -1) {
    int saved = errno;
    vexiterr(EXIT_DEFER, ERROR, "", "lseek error rewinding stdin: %s", strerror(saved));
  }
}


// qmail-local writes Unable to switch to _ (#4.3.0). and defers [todo: check]
void Chdir(const char *path) {
  if (chdir(path) == -1) {
    int saved = errno;
    vexiterr(EXIT_DEFER, ERROR, "", "chdir failed, path=%s reason=%s",path,strerror(saved));
  }
}


// Safe version of vauth_getpw(). Defers if the auth backend cannot be reached.
// Return value: a vqpasswd record, or NULL when not-found.
struct vqpasswd *Vauth_getpw(char *user, char *domain) {
  struct vqpasswd *pw;

  pw = vauth_getpw(user, domain);
  if (pw == NULL && verrori != 0) { // e.g. VA_NO_AUTH_CONNECTION
    vexiterr(EXIT_DEFER, ERROR, "vdelivermail: deferred, database down", "can't lookup vpopmail user, verrori=%d",verrori); // same message as v5.6
  }
  return pw;
}



// Same merge vlimits_setflags() does, but returned rather than written
// into dest_owner->pw_flags.
// Also we apply better error handling.
// pw_gid - the user's own flags bitmask, from their db record
// local_part, domain - whose flags these are; local_part corresponds to vpopmail.pw_name
void calc_effective_flags(gid_t pw_gid, const char *local_part, const char *domain, gid_t *flags_out) {
  struct vlimits domain_limits;

  if (pw_gid & V_OVERRIDE) {
    *flags_out = pw_gid;
  } 
  else if (vget_limits(domain, &domain_limits) == 0) { // reads  ~vpopmail/etc/vlimits.default if there are no db rows
    *flags_out = pw_gid | vlimits_get_flag_mask(&domain_limits);
  } 
  else { // vget_limits failed, stick with the owner's own gid.
    log_event(ERROR, "Failed to load domain limits for %s@%s, using user-level limits only",local_part,domain);
    *flags_out = pw_gid;
  }
}



/* Splits an email address into the local part and the domain.
 * An address without "@" is taken to be local part only.
 * An address with two @'s will get @'s in the domain part.
 * Output: localpart_out, domain_out must be AUTH_SIZE. Pass a NULL for any outputs you don't need.
 *
 * Not using parse_email() because it lowercases and truncates its input in-place.
 * lowerit() stops at 156 bytes, and on a domain-less input
 * it does not leave the domain empty but invents one via vset_default_domain(),
 * which also writes through a getenv() pointer. 
 */
void split_email(char *localpart_out, char *domain_out, const char *address) {
  const char *at = strchr(address, '@');

  if (at == NULL) {
    if (localpart_out) snprintf(localpart_out, AUTH_SIZE, "%s", address);
    if (domain_out) domain_out[0] = '\0';
    return;
  }

  if (localpart_out) snprintf(localpart_out, AUTH_SIZE, "%.*s", (int)(at - address), address);
  if (domain_out) snprintf(domain_out, AUTH_SIZE, "%s", at + 1);
}


/* Copies src into dst, lowercasing ASCII A-Z. Other bytes, including UTF-8, are copied
 * unchanged, so the result doesn't depend on the locale.
 *
 * Use this rather than vpopmail.c lowerit(), which modifies its argument in place and
 * silently truncates it at 156 bytes.
 *
 * Returns 0 on success, -1 on failure (when src does not fit in dst_size) */
int lowercase_copy(char *dst, size_t dst_size, const char *src) {
  size_t i;

  if (dst_size == 0) return -1;
  for (i = 0; src[i] != '\0'; i++) {
    if (i + 1 >= dst_size) {
      dst[i] = '\0';
      return -1;
    }
    unsigned char c = (unsigned char)src[i];
    dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
  }
  dst[i] = '\0';
  return 0;
}


// Copy one string field of a struct vqpasswd into buf. A NULL src leaves buf unchanged.
void copy_pw_string(const char *field, const char *src, char *buf, size_t size) {
  if (src == NULL) return;
  if ((size_t)snprintf(buf, size, "%s", src) >= size) {
    log_event(ERROR, "The %s field from the db is too long: %s...",field,buf);
  }
}


/* Copy the fields vdelivermail uses from src into dst, so they stay valid after further
 * vauth_getpw() calls. A NULL string becomes empty. */
void copy_vqpasswd(vqpasswd_copy_t *dst, const struct vqpasswd *src) {
  memset(dst, 0, sizeof *dst);
  dst->pw_gid = src->pw_gid;
  copy_pw_string("pw_name", src->pw_name, dst->name, sizeof dst->name);
  copy_pw_string("pw_dir", src->pw_dir, dst->dir, sizeof dst->dir);
  copy_pw_string("pw_shell", src->pw_shell, dst->quota_allocation_string, sizeof dst->quota_allocation_string);
}


/* Look up user@domain and copy the record into *copy, so it survives later vauth_getpw() calls.
 *
 * Why this exists: vauth_getpw() doesn't return a record of its own. It returns a pointer to one
 * static struct vqpasswd inside the auth backend, whose string fields point into the backend's
 * static buffers (see vmysql.c). Every call overwrites that same storage, so the next lookup of
 * any user silently changes what earlier callers are holding. Keeping the pointer in a local
 * variable doesn't help, and neither does a struct copy: its strings still point into the
 * shared buffers. Lookups also happen where you can't see them, e.g. make_user_dir() calls
 * vauth_getpw() itself. v5.6 kept the result in the global vpw, which made a second lookup
 * (a maildir owner, or a re-read after make_user_dir()) unsafe.
 *
 * copy->domain is the real domain if domain is an alias.
 * Returns 0 on success, or -1 if there's no such user, leaving *copy zeroed.
 * A database failure defers, as in Vauth_getpw(). */
int load_user(vqpasswd_copy_t *copy, const char *user, const char *domain) {

  // vauth_getpw() lowercases both, and vget_assign() rewrites an alias domain as the real one.
  char user_buf[MAX_PW_NAME + 1];
  char domain_buf[MAX_PW_DOMAIN + 1]; // the size vget_assign() assumes

  // Prevent vget_assign() from receiving a domain that it would silently truncate.
  // Such domains would exceed db field length, so it's safe to return not-found, rather than raising a fatal exception.
  if ((size_t)snprintf(user_buf, sizeof user_buf, "%s", user) >= sizeof user_buf ||
      (size_t)snprintf(domain_buf, sizeof domain_buf, "%s", domain) >= sizeof domain_buf) {
    log_event(DEBUG, "not looking up %s@%s: longer than MAX_PW_NAME (%d) or MAX_PW_DOMAIN (%d), returning no-such-user",
              user, domain, MAX_PW_NAME, MAX_PW_DOMAIN);
    memset(copy, 0, sizeof *copy);
    return -1;
  }

  struct vqpasswd *pw = Vauth_getpw(user_buf, domain_buf);
  if (pw == NULL) {
    memset(copy, 0, sizeof *copy);
    return -1;
  }
  copy_vqpasswd(copy, pw);
  copy_pw_string("domain", domain_buf, copy->domain, sizeof copy->domain);
  return 0;
}


int open_current_directory(void) {
  int fd = open(".", O_RDONLY);
  if (fd == -1) {
    int saved = errno;
    vexiterr(EXIT_DEFER, ERROR, "", "open(\".\") failed: %s",strerror(saved));
  }
  return fd;
}

/* Strips a single trailing '\n' from s, in place, if present. */
static void trim_newline(char *s) {
  size_t n = strlen(s);
  if (n > 0 && s[n - 1] == '\n') s[n - 1] = '\0';
}


/* Extract the return path address from the RPLINE environment variable.
  RPLINE comes in as "Return-Path: <quoted-sender>\n", that is,
  literally "Return-Path:" at the beginning of the string,
  with angle brackets around the address.

  Return value: 0 on success, 1 when we detect invalid input.
  Output: rp_out - to hold the bare email address. Empty string means the null sender address.
          err - a struct to allow the caller to log and exit at an appropriate moment.
  Invalid UTF-8 sequences and most control characters are passed through, as is. Only our log sees the sanitised version.
*/
int parse_rpline(char* rp_out, size_t rp_size, const char *rp, pending_exit_t *err) {
  size_t n;
  size_t i;
  size_t inner;
  const char *p = rp;

  char log_rp[256];
  snprintf(log_rp, sizeof log_rp, "%s", rp);
  trim_newline(log_rp);
  sanitise_inplace(log_rp, sizeof log_rp, false, NULL, NULL);

  if (strncasecmp(p, "Return-Path:", 12) != 0) {
    vexiterr_pend(err, EXIT_DEFER, ERROR, "", "RPLINE environment variable lacks \"Return-Path:\" prefix: %s", log_rp);
    return 1;
  }
  p += 12;
  while (*p == ' ' || *p == '\t') {
    ++p;
  }

  n = strlen(p);
  while (n > 0 && (p[n - 1] == '\n' || p[n - 1] == '\r')) {
    --n;
  }
  for (i = 0; i < n; i++) {
    if (p[i] == '\n' || p[i] == '\r') {
      // Bounce is best, as qmail would pass through \r, and no amount of defer'ing would fix it.
      vexiterr_pend(err, EXIT_BOUNCE, ERROR, "", "RPLINE contains a newline: %s", log_rp);
      return 1;
    }
  }
  if (n < 2 || p[0] != '<' || p[n - 1] != '>') {
    vexiterr_pend(err, EXIT_DEFER, ERROR, "", "RPLINE environment variable lacks angle brackets around the Return-Path value: %s", log_rp);
    return 1;
  }

  inner = n - 2;
  if (inner >= rp_size) {
    // Bounce is best, in case a queued message has it. Not fixed by defer.
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "", "RPLINE too long: %s", log_rp);
    return 1;
  }

  memcpy(rp_out, p + 1, inner);
  rp_out[inner] = '\0';
  return 0;
}


static const char *angle_bracketed(const char *s) {
  static char buf[RETURN_PATH_SIZE + 3];
  snprintf(buf, sizeof buf, "<%s>", s);
  return buf;
}



/* Append "Name: value\n" to buf. buf must already be a NUL-terminated string
  ("" to start a new block). A trailing CR/LF on value is ignored. CR/LF (or
  ':') in name or value, a NULL/empty name, a NULL value, and overflow are
  programmer errors: log and skip the header, do not defer as that could jeopardize deliver_quota_warning, for example,
   which has a contract with the caller not to exit or printf.
  Callers must
  sanitise inputs. No begin/reset helper: each write path uses a local
  `char extra_headers[HEADERS_SIZE] = ""`. */
static void add_header(char *buf, size_t bufsize, const char *name,
                       const char *value) {
  size_t used;
  size_t valuelen;
  size_t i;
  int r;

  if (name == NULL || *name == '\0' || value == NULL) {
    log_event(ERROR, "internal error: missing delivery header");
    return;
  }
  for (i = 0; name[i] != '\0'; i++) {
    if (name[i] == '\r' || name[i] == '\n' || name[i] == ':') {
      log_event(ERROR, "delivery header name %s is invalid", name);
      return;
    }
  }

  valuelen = strlen(value);
  while (valuelen > 0 &&
         (value[valuelen - 1] == '\n' || value[valuelen - 1] == '\r')) {
    --valuelen;
  }
  for (i = 0; i < valuelen; i++) {
    if (value[i] == '\r' || value[i] == '\n') {
      log_event(ERROR, "delivery header %s contains a newline", name);
      return;
    }
  }

  used = strlen(buf);
  if (used >= bufsize) {
    log_event(ERROR, "delivery headers too long for %s", DealiasedRecipient);
    return;
  }
  r = snprintf(buf + used, bufsize - used, "%s: %.*s\n", name, (int)valuelen,
               value);
  if ((size_t)r >= bufsize - used) {
    log_event(ERROR, "delivery headers too long for %s", DealiasedRecipient);
    return;
  }
}


// Number of elements in a NULL-terminated char** array (not counting the terminator).
// A NULL pointer is treated as an empty array and returns 0.
int array_count(char** lines) {
  int rows = 0;
  if (lines == NULL) return 0;
  while (lines[rows] != NULL) {
    rows++;
  }
  return rows;
}


// Append a copy of line to a malloc'd NULL-terminated char** array.
// *lines must already be that array (possibly empty). Caller frees with free_array.
void array_push(char*** lines, char* line) {
  int rows;
  char** tmp;
  char* copy;

  rows = array_count(*lines);

  tmp = realloc(*lines, sizeof(char*) * (rows + 2));
  if (tmp == NULL) {
    vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
  };
  *lines = tmp;

  copy = malloc(strlen(line) + 1);
  if (copy == NULL) {
    vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
  };
  strcpy(copy, line);

  (*lines)[rows] = copy;
  (*lines)[rows + 1] = NULL;
}


// Call after fgets(buf, size, f) returned non-NULL. Returns true if the physical line
// didn't fit in buf, and skips the rest of it so that the next fgets() starts on the
// following line. A line that exactly fills buf before its newline is not truncated:
// the newline is consumed.
// The newline is looked for with memchr() across all size - 1 bytes fgets() may have
// stored, not at strlen(): a NUL inside the line must not make it look truncated, or the
// line after it would be skipped. Bytes past the line can be stale only when fgets()
// stopped at EOF, and then there is nothing left to skip either way.
bool fgets_truncated(const char *buf, size_t size, FILE *f) {
  int c;

  if (memchr(buf, '\n', size - 1) != NULL) return false; // whole line read
  if (feof(f)) return false;                             // last line, no trailing newline
  c = getc(f);
  if (c == EOF || c == '\n') return false;               // fit exactly
  do {
    c = getc(f);
  } while (c != EOF && c != '\n');
  return true;
}


void free_array(char** instructions) {
  if (instructions == NULL) return;
  for (int i=1; instructions[i-1] != NULL; i++) {
    free(instructions[i-1]);
  }
  free(instructions);
}


// Creates a NULL terminated array. Caller should free when finished.
// Elements are strings. There are no newline characters on the end.
// Return value: 0 on success, -1 on absent, -2 if it can't be read: an open or read error,
// or a line longer than MAX_BUFF - 1 (logged). *lines_out is NULL unless it succeeded.
int load_text_file(const char *filename, char*** lines_out) {
  char line[MAX_BUFF];
  FILE* file;
  int limit;
  bool failed = false;

  *lines_out = NULL;
  file = fopen(filename, "r");
  if (file == NULL) {
    if (errno == ENOENT) {
      return -1;
    };
    log_event(ERROR, "Error opening file %s: %s", filename, strerror(errno));
    return -2;
  };

  if (! (*lines_out = malloc(sizeof(char*)))) {
    vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
  };
  (*lines_out)[0] = NULL;

  // fgets will retain \n at the end of the line.
  // A \0 ends that line's value: consumers of the array see only what precedes it.
  // Following lines are unaffected.
  while (fgets(line, sizeof(line), file) != NULL) {
    if (fgets_truncated(line, sizeof(line), file)) {
      log_event(ERROR, "Line is too long in %s: %.80s...", filename, line);
      failed = true;
      break;
    }

    limit = strlen(line);
    if (limit > 0 && line[limit-1] == '\n') { limit--; };
    if (limit > 0 && line[limit-1] == '\r') { limit--; };
    line[limit] = '\0';
    array_push(lines_out, line);
  };
  if (!failed && ferror(file)) {
    log_event(ERROR, "Error reading file %s: %s", filename, strerror(errno));
    failed = true;
  }
  fclose(file);

  if (failed) {
    free_array(*lines_out);
    *lines_out = NULL;
    return -2;
  }
  return 0;
};


int count_non_comment_instructions(char** instructions) {
  int count=0;
  for (int i=1; instructions[i-1] != NULL; i++) {
    if (instructions[i-1][0] != '#') {
      count++;
    }
  }
  return count;
}


// Remove comments and empty lines. Makes it easier to detect when there's a mixture of success and failure while executing the delivery instructions.
void clean_instructions(char*** lines_out, char** instructions) {
  int rows=0;
  char** tmp;
  char line[MAX_BUFF];
  char* tmp2;
  char* p;
  
  if (! (*lines_out = malloc(sizeof(char*) * 2))) {
    vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
  };
  (*lines_out)[0] = NULL;

  for (int i=1; instructions[i-1] != NULL; i++) {
    snprintf(line, sizeof(line), "%s", instructions[i-1]);

    p=line;
    if (*p == '\0') { continue; }; // discard empty lines
    if (*p == '#') { continue; }; // discard comment lines

    // Now we have at least one character. Remove trailing whitespace including newline characters.
    p = line + strlen(line) - 1;
    while (isspace(*p)) p--;
    p++;
    *p = '\0';
    if (strlen(line) == 0) { continue; }; // if the line was only whitespace, discard it.

    /*
    // Note: the v5.6 default .qmail-default file has "| " 
    // Philosophy: If we are more generous that qmail-local, mention the more aggregious issues as a WARN in my validate routine.

    // Remove spaces after &, |, :
    if (line[0] == '&' || line[0] == '|' || line[0] == ':') {
      p = line + 1;
      while (isspace(*p)) p++;
      if (*p == '\0') { continue; }; // invalid, but not this functions's job to fix it.
      memmove(line+1,p,strlen(p)+1); // moves everything (including the \0) from the third position onwards, to the second position.
    }
    else { // Assume email address and remove leading spaces. If we hit a stray "|" or similar, that will be caught elsewhere.
      p=line;
      while (isspace(*p)) p++;
      // The tests ensure we don't cause illegally indented lines to be accepted:
      if (*p != '#' && *p != '|' && *p != '.' && *p != '/' && *p != ':' && *p != '&') {
        memmove(line,p,strlen(p)+1); // remove those leading spaces
      }
    }
    */

    rows++;
    tmp = realloc(*lines_out, sizeof(char*) * (rows + 1));
    if (tmp == NULL) {
      vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
    };
    *lines_out = tmp;

    tmp2 = malloc(sizeof(char) * (strlen(line) + 1));
    if (tmp2 == NULL) {
      vexiterr(EXIT_DEFER, ERROR, "", "Error allocating memory");
    };
    (*lines_out)[rows-1] = tmp2;
    strcpy((*lines_out)[rows-1], line);
  }

  (*lines_out)[rows] = NULL;
}


int validate_shell_command(char* line) {
  if (strstr(line, "vdelivermail") != NULL) {
    printf("ERROR Calling vdelivermail from vpopmail's defaultdelivery file is deprecated.\n");
    return 0; // fatal in test mode, accepted in production for backward compatability
  }
  return 1;
}


int validate_path_to_maildir(char* line) {
  // Detect programming error
  // if (line[0] != '.' && line[0] != '/') {
  //   printf("ERROR: unexepcted first character for path to Maildir");
  //   return 0;
  // };

  // TODO: disallow newlines.

  // Unlike qmail-local, we only allow Maildirs, not mbox files.
  if (line[strlen(line) - 1] != '/') {
    printf("ERROR: can't handle mbox delivery for %s", line);
    return 0;
  }

  // No internal spaces? No quotes?

  return 1;
}


// Whilst we could rely on qmail-inject to validate the address, it's valuable to validate
// here in case the user accidentally passes a shell command or Maildir path without the correct punctuation.
int validate_forwarding_address(char* line, int check_mode) {
  char local_part[AUTH_SIZE];
  char domain[AUTH_SIZE];
  char msg[MAX_BUFF];

  if (strstr(line,"@") != NULL) {
    if (strlen(line) >= AUTH_SIZE) {
      snprintf(msg, sizeof msg, "invalid email address - too long: %.80s...", line);
      if (check_mode) {
        printf("ERROR: %s",msg);
      }
      else {
        vexiterr(EXIT_BOUNCE, ERROR, "", "%s",msg);
      };
      return 0;
    }
    split_email(local_part, domain, line); // avoids parse_email's side-effects

    // is_username_valid() rejects "%"
    if (local_part[0] == '\0' || domain[0] == '\0' ||
        is_username_valid(local_part) != 0 || is_domain_valid(domain) != 0) {
      snprintf(msg, sizeof msg, "invalid email address: %s", line);
      if (check_mode) {
        printf("ERROR: %s",msg); 
      } 
      else {
        vexiterr(EXIT_BOUNCE, ERROR, "", "%s",msg);
      };
      return 0;
    }
  }
  else {
    // Only local part present, qmail should use /var/qmail/control/envnoathost to determine the domain name
    if (is_username_valid(line) != 0) {
      snprintf(msg, sizeof msg, "invalid local-part-only email address: %s", line);
      if (check_mode) {
        printf("ERROR: %s",msg); 
      } 
      else {
        vexiterr(EXIT_BOUNCE, ERROR, "", "%s",msg);
      };
      return 0;
    }
  }
  return 1;
}


// in a defaultdelivery file, we reject everything
int validate_directive(char* line) {
  if (strcmp(line,":default") == 0) {
    printf("ERROR: :default is only valid in the valias table\n");
    return 0;
  }

  printf("Invalid delivery instruction: %s", line);
  return 0; // sic
}


/*
 * Get the size of the email message. Stdin must already be a regular
 * file (a pipe's st_size is 0). Does not move the file position; each stdin
 * consumer rewind_stdin()s before it reads.
 */
ssize_t get_message_size() {
  struct stat st;

  if (fstat(0, &st) < 0) {
    vexiterr(EXIT_DEFER, ERROR, "", "fstat error %d during get_message_size", errno);
  }
  return (ssize_t)st.st_size;
}


/*
 * Get the command line arguments and the environment variables.
 * Force addresses to be lower case and set the default domain.
 *
 * Options (GNU getopt: may appear anywhere on the command line):
 *   -v  print version and exit
 *   -V  verbose
 *   -h  help
 *   -d  dump message to stdout instead of Maildir (also: DELIVER_TO_STDOUT=1)
 *
 * Positionals after options:
 *   vdelivermail              → bounce = "default"
 *   vdelivermail ""           → bounce = "default"
 *   vdelivermail "" <bounce>  → bounce as given (compat arg must be "")
 *   vdelivermail <bounce>     → invalid (compat "" required when bounce given)
 */
void print_version(void) {
  printf("vdelivermail version %s\n", VERSION);
}


void usage(void) {
  printf("vdelivermail: usage: [options] \"\" instruction\n");
  printf("options: -v, --version (print version number)\n");
  printf("         -V (verbose)\n");
  printf("         -h, --help (this help)\n");
  printf("         -d (dump delivery to stdout instead of Maildir)\n");
  printf("\ninstruction - what to do for user-not-found:\n");
  printf("  delete | bounce-no-mailbox | <email> | <Maildir>\n"); // the documented Maildir form is incorrect
  printf("\nExamples:\n");
  printf("  vdelivermail \"\" delete\n");
  printf("  EXT=user HOST=example.com ./vdelivermail -d \"\" delete < test.eml\n");
}


void process_interactive_mode_switches(int argc, char **argv) {
  int c;

  // Options
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      usage();
      exit(0);
    }
    if (strcmp(argv[i], "--version") == 0) {
      print_version();
      exit(0);
    }
  }

  // For -h, -v we assume being run from command line, rather than from within .qmail-default
  // If we needed additional safety, we could always EXIT_DEFER when getenv("DEFAULT") != NULL.
  while ((c = getopt(argc, argv, "tvdVh")) != -1) {
    switch (c) {
      case 'h':
        usage();
        exit(0);
      case 'v':
        print_version();
        exit(0);
      case 'V':
      case 'd':
        break; // process -V and -d later
      default:
        // Probably better not to show usage(), in case we're being run from within .qmail-default
        printf("invalid option: %c\n", c); // logging system not loaded yet
        exit(0);
    }
  }
}


// returns 0 if running within qmail-default
int check_qmail_default(void) {
  return getenv("DEFAULT") == NULL ? 1 : 0;
}


// If /var/qmail/users/cdb is on local disk, this doesn't hit the network.
// Sets DealiasedRecipient, TheDomain, TheDomainDir, TheDomainUid, TheDomainGid
int lookup_domain_globals(char* original_domain, pending_exit_t *err) {
  int r;

  // get_environment already validated and lowercased HOST, which is what original_domain holds.
  snprintf(TheDomain, sizeof(TheDomain), "%s", original_domain);

  // Prevent vget_assign() from receiving a domain that it would silently truncate.
  // vadddomain would have refused such values anyway.
  if (strlen(TheDomain) > MAX_PW_DOMAIN) {
    vexiterr_pend(err, EXIT_BOUNCE, INFO, "invalid domain name",
                  "$M: input was %zu bytes, max is %d bytes, domain=%s",
                  strlen(TheDomain), MAX_PW_DOMAIN, TheDomain);
    return 1;
  }

  // vget_assign will modify TheDomain if it's an alias domain. It also lowercases it.
  if (NULL==vget_assign(TheDomain, TheDomainDir, sizeof(TheDomainDir), &TheDomainUid, &TheDomainGid)) {
    // e.g. empty/NULL domain, CDB unreadable, domain not present, cdb_seek error
    vexiterr_pend(err, EXIT_DEFER, ERROR, "", "Domain cdb file lookup failed, domain=%s", original_domain);
    return 1;
  };

  /* TheDomain is now the real domain, so this is the address every Delivered-To
   * line will carry and the address main() checks for loops. We are writing the dealiased
   * form deliberately: it collapses every alias spelling of the account into one
   * token, so a loop arriving via any alias domain is still caught. */
  r = snprintf(DealiasedRecipient, sizeof(DealiasedRecipient), "%s@%s", TheUser,
               TheDomain);
  if ((size_t)r >= sizeof(DealiasedRecipient)) {
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "vdelivermail: email too long", /* v5.6 message */
     "recipient email address too long: %.80s...", DealiasedRecipient);
    return 1;
  }

  snprintf(gelf.context.domain, sizeof gelf.context.domain, "%s", TheDomain); // after dealiasing
  return 0;
}


// Process environment variables.
// Process HOST first, then EXT, so we can write gelf.context.to as early as possible.
// Returns 0 on success. 
// Returns 1 on failure, and populates err
int get_environment(pending_exit_t *err) {
  char *tmpstr;
  
  char log_inputs[640]; // sized to fit three env variables. Keep this length under logmsg's 1024 bytes.
  snprintf(log_inputs, sizeof(log_inputs), "EXT=%s HOST=%s SENDER=%s", getenv("EXT") ?: "(unset)", getenv("HOST") ?: "(unset)", getenv("SENDER") ?: "(unset)");
  sanitise_inplace(log_inputs, sizeof(log_inputs), false, NULL, NULL);

  if ((tmpstr = getenv("HOST")) == NULL) { // Consider defer, as it's a fixable config error
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "vdelivermail: no HOST environment varilable", "$M, %s",log_inputs); // v.5.6 message, but it noticed no EXT first
    return 1;
  }

  if (is_domain_valid(tmpstr) != 0) {
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "invalid domain name", "$M, %s", log_inputs);
    return 1;
  }

  // A copy, not lowerit(): lowercasing the getenv() pointer in place would rewrite our
  // own environment, which children we exec would then inherit.
  if (lowercase_copy(OriginalDomain, sizeof(OriginalDomain), tmpstr) != 0) { // i.e. HOST
    vexiterr_pend(err, EXIT_BOUNCE, INFO, "invalid domain name", "$M: HOST at %zu bytes, is too long. %s",
                  strlen(tmpstr), log_inputs);
    return 1;
  }

  if ((tmpstr = getenv("EXT")) == NULL) { // Consider defer, as it's a fixable config error
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "vdelivermail: no EXT environment varilable", "$M, %s", log_inputs); // v5.6 message
    return 1;
  }

  if (is_username_valid(tmpstr) != 0) {
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, "invalid username", "$M (EXT) invalid, %s", log_inputs);
    return 1;
  }

  if (lowercase_copy(TheUser, sizeof(TheUser), tmpstr) != 0) { // i.e. EXT
    vexiterr_pend(err, EXIT_BOUNCE, INFO, "invalid username", "$M (EXT) too long, %zu bytes, %s",
                  strlen(tmpstr), log_inputs);
    return 1;
  }

  if ((size_t)snprintf(OriginalRecipient, sizeof(OriginalRecipient), "%s@%s", TheUser, OriginalDomain)
      >= sizeof(OriginalRecipient)) {
    vexiterr_pend(err, EXIT_BOUNCE, INFO, "vdelivermail: email too long", /* v5.6 message */
                  "recipient email address too long, max is %zu bytes. %s", sizeof(OriginalRecipient) - 1, log_inputs);
    return 1;
  }
  snprintf(gelf.context.to, sizeof gelf.context.to, "%s", OriginalRecipient); // before dealiasing

#ifdef QMAIL_EXT
  int i;
  /* !! Shouldn't this work its way backwards, and try all possibilities?
   * e.g., a-b-c-d should try a-b-c then a-b then a, instead of just a?
   */
  /* delete the '-' and following chars if any and store in TheUserExt */
  for (i = 0; (TheUser[i] != 0) && (TheUser[i] != '-'); i++) {
    TheUserExt[i] = TheUser[i];
  }
  TheUserExt[i] = 0;

  // This test is in v5.6, but never fires now, as we tested the EXT env variable above.
  if (is_username_valid(TheUserExt) != 0) {
    vexiterr_pend(err, EXIT_BOUNCE, ERROR, NULL, "invalid username, username=%s, %s", TheUserExt, log_inputs);
    return 1;
  }

  // Everything after the first '-', or empty if there is none. 
  // The test for TheUser[i] == '-' prevents trying to read past the null terminator when there is no "-".
  snprintf(TheExt, sizeof TheExt, "%s", TheUser[i] == '-' ? &TheUser[i + 1] : "");
  for (i = 0; (TheExt[i] != 0); i++) {
    if (TheExt[i] == '.') TheExt[i] = ':';
  }
#endif

  if (getenv("RPLINE") == NULL) {
    vexiterr_pend(err, EXIT_DEFER, ERROR, "vdelivermail: no RPLINE environment variable", "$M, %s", log_inputs);
    return 1;
  }
  if (parse_rpline(ReturnPath, sizeof ReturnPath, getenv("RPLINE"), err) != 0) {
    return 1;
  }
  snprintf(gelf.context.from, sizeof gelf.context.from, "%s", ReturnPath); // before dealiasing. could be empty string
  sanitise_inplace(gelf.context.from, sizeof gelf.context.from, false, NULL, NULL); // ReturnPath itself unmodified
  gelf.context.from_known = true;

  if (getenv("DELIVER_TO_STDOUT") != NULL) { DeliverToStdout = 1; }

  return 0;
}


void get_arguments(int argc, char **argv) {
  int remaining_arguments;
  int c;
  extern int optind; // the index in argv of the next argument to process
#if HAVE_DECL_OPTRESET
  extern int optreset; // BSD only; not present on Linux glibc
#endif

  // Long options
  for (int i = 1; i <= argc; i++) {
    if (strcmp(argv[i-1], "--help") == 0 || strcmp(argv[i-1], "--version") == 0) {
      vexiterr(EXIT_DEFER, ERROR,"","%s not accepted when DEFAULT environment variable is set", argv[i-1]);
    }
  }

  // For -h, -v we assume being run from command line, rather than from within .qmail-default
  // If we needed additional safety, we could always EXIT_DEFER when getenv("DEFAULT") != NULL.
  optind = 1;
#if HAVE_DECL_OPTRESET
  optreset = 1;
#endif
  while ((c = getopt(argc, argv, "tvdVh")) != -1) {
    switch (c) {
      case 'h':
      case 't':
      case 'v':
        // -h/-v already exited, if DEFAULT was not set.
        vexiterr(EXIT_DEFER, ERROR,"","%c not accepted when DEFAULT environment variable is set",c);
      case 'V':
        Verbose = 1;
        break;
      case 'd':
        DeliverToStdout = 1;
        break;
      default:
        vexiterr(EXIT_DEFER, ERROR,"","Invalid option -%c",c);
    }
  }

  // Positional arguments
  char generic_message[] = "vdelivermail: invalid syntax in .qmail-default file"; // from v5.6.
  remaining_arguments = argc - optind;
  if (remaining_arguments >= 1 && argv[optind][0] != '\0') {
    vexiterr(EXIT_DEFER, ERROR, generic_message, "$M, first argument must be empty string");
  }
  if (remaining_arguments == 2) {
    if (strcmp(argv[optind + 1], ":default") == 0) {
      vexiterr(EXIT_DEFER, ERROR, generic_message, "$M, :default not valid for the user-not-found instruction");
    };
    if ((size_t)snprintf(bounce, sizeof(bounce), "%s", argv[optind + 1]) >= sizeof(bounce)) {
      vexiterr(EXIT_DEFER, ERROR, generic_message, "$M, user-not-found instruction too long, max is %zu bytes", sizeof(bounce) - 1);
    }
    if (strlen(bounce) == 0) {
      vexiterr(EXIT_DEFER, ERROR, generic_message, "$M, user-not-found instruction cannot be an empty string");
    }
  }
  else if (remaining_arguments > 2) {
    vexiterr(EXIT_DEFER, ERROR, generic_message, "$M, too many arguments");
  }
}


// Allocate a path, create the user dir + Maildir tree on disk.
// Only triggers when pw_dir is blank.
// USERS_BIG_DIR hashing uses domain counters/slots, so the path is not derived from the username alone.
// Unlike vadduser -q, it doesn't create maildirsize.
void ensure_homedir_is_set_in_db(vqpasswd_copy_t *recipient_inout) {
  // Nothing to do unless the db has no homedir for this user.
  if (recipient_inout->dir[0] != '\0') { // also covers a NULL pw_dir: dir is then empty
    return;
  }
  // Creates Maildir, Maildir/new, Maildir/cur, Maildir/tmp
  // With SPAM_JUNKFOLDER, creates Maildir/.Junk, Maildir/.Junk/new, Maildir/.Junk/cur, Maildir/.Junk/tmp
  // Calls vauth_getpw internally, which overwrites the backend's static storage but not our copy.
  // It also lowercases its name and domain arguments in place, and vget_assign() can rewrite
  // the domain, so we pass copies. The domain copy is the MAX_PW_DOMAIN + 1 that vget_assign() assumes.
  char name_copy[MAX_PW_NAME + 1];
  char domain_copy[MAX_PW_DOMAIN + 1];
  snprintf(name_copy, sizeof name_copy, "%s", recipient_inout->name);
  snprintf(domain_copy, sizeof domain_copy, "%.*s", MAX_PW_DOMAIN, TheDomain); // lookup_domain_globals() rejected longer
  if (make_user_dir(name_copy, domain_copy, TheDomainUid, TheDomainGid) == NULL) {
    vexiterr(EXIT_BOUNCE, ERROR, "Auto creation of maildir failed. (#5.9.8)", "$M");
  }
  // make_user_dir also populates the homedir field in the db (then frees its
  // temporary pw_dir pointer, so the backend's pw_dir is not usable afterward).
  // Re-read the entry, to gain access to the new pw_dir entry. Only pw_dir changed, so only it is copied.
  vqpasswd_copy_t reloaded;
  if (load_user(&reloaded, recipient_inout->name, recipient_inout->domain) != 0) {
    vexiterr(EXIT_BOUNCE, ERROR, "Failed to vauth_getpw(). (#5.9.8.1)", "$M"); // e.g. user not found. v5.6 wording
  };
  copy_pw_string("pw_dir", reloaded.dir, recipient_inout->dir, sizeof recipient_inout->dir);
}


// If pw_dir is already set but that directory is missing on disk, recreate it
// (hash dirs, user dir, Maildir/{cur,new,tmp}, and .Junk if enabled). Does not
// change the db. Does nothing if the user dir exists, even when Maildir does not.
void ensure_homedir_exists_on_disk(const vqpasswd_copy_t *recipient) {
  struct stat mystatbuf;
  
  if (recipient->dir[0] == '\0') { // also covers a NULL pw_dir: dir is then empty
    vexiterr(EXIT_DEFER, ERROR, "", "homedir field is empty for %s@%s", recipient->name, recipient->domain);
  }

  /* check if the directory exists and create if needed */
  if (stat(recipient->dir, &mystatbuf) == -1) {
    if (vmake_maildir(TheDomain, (char *)recipient->dir) != VA_SUCCESS) { // cast away const: vmake_maildir only reads dir
      vexiterr(EXIT_BOUNCE, ERROR, "Auto re-creation of maildir failed. (#5.9.9)", "$M");
    }
  }
}


// 0=success, -1 on not found, -2 on other errors.
// Output: qbuf is empty string on failure.
int read_quota_from_maildir(const char *maildir, char *qbuf, size_t qlen) {
  FILE *quota_file;
  char quotafn[PATH_MAX];
  char *newline;

  *qbuf = '\0';
  if ((size_t)snprintf(quotafn, sizeof(quotafn), "%s/maildirsize", maildir) >= sizeof(quotafn)) {
    // Not -1: a truncated name says nothing about whether maildirsize exists.
    log_event(ERROR, "maildir path too long, unable to check maildirsize. It was %zu bytes long: %s", strlen(maildir), maildir);
    return -2;
  }
  quota_file = fopen(quotafn, "r");
  if (quota_file == NULL) {
    if (errno == ENOENT) {
      return -1;
    }
    log_event(ERROR, "Error opening file %s: %s", quotafn, strerror(errno));
    return -2;
  }
  
  if (fgets(qbuf, qlen, quota_file) == NULL) {
    // fgets() returns NULL both at EOF and on error, and only the error sets errno.
    if (feof(quota_file)) {
      log_event(ERROR, "%s is empty", quotafn);
    }
    else {
      log_event(ERROR, "Error while reading %s: %s", quotafn, strerror(errno));
    }
    fclose(quota_file);
    *qbuf = '\0';
    return -2;
  }
  if (fgets_truncated(qbuf, qlen, quota_file)) {
    log_event(ERROR, "%s quota line is too long. Max is %zu bytes", quotafn, qlen - 1);
    fclose(quota_file);
    *qbuf = '\0';
    return -2;
  }
  fclose(quota_file);
  newline = strchr(qbuf, '\n');
  if (newline != NULL) *newline = '\0';
  return 0;
}


void sig_catch(int sig, void (*f)(int))
{
#ifdef HAVE_SIGACTION
  struct sigaction sa;
  sa.sa_handler = f;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(sig, &sa, (struct sigaction *)0);
#else
  signal(sig, f); /* won't work under System V, even nowadays---dorks */
#endif
}


// RETURN VALUE: -1 mean stop processing remaining delivery instructions
int run_command(char *prog, const char *log_source) { 
  int child_pid;
  int wstat;
  int xcode;
  char *(args[4]);
  delivery_log_t *d = &gelf.context.delivery;
  int saved_errno;
  int ret;
  char msg[HEADER_VALUE_MAX];

  memset(d, 0, sizeof *d);
  d->in_progress = true;
  snprintf(d->instruction, sizeof d->instruction, "%s", prog);
  d->source = log_source;
  d->method = "program";
  snprintf(d->message, sizeof d->message, "Running shell command, recipient is %s", OriginalRecipient); // refine later

  rewind_stdin();

  while ((*prog == ' ') || (*prog == '|')) ++prog;

  // OriginalRecipient accords with EXT and USER, as inherited by the command.
  //
  // We can't extract the path to the program run by the shell command, without making a lot of assumptions.
  // So just sniff for the handful of commands that dominate in practice, the way vutil.c's
  // isExistingAlias() already does for valias rows containing ezmlm and autorespond. 
  // qmail-start(8) documents putting QMAILHOME/bin on PATH for the whole delivery tree, so don't insist on a leading '/'.
  // A wrong guess costs nothing: d->instruction carries the verbatim command in the same log record.
  if (strstr(prog, "autorespond"))
    snprintf(d->message, sizeof d->message, "Running autorespond command, recipient is %s", OriginalRecipient);
  else if (strstr(prog, "lmtp"))
    snprintf(d->message, sizeof d->message, "Running LMTP command, recipient is %s", OriginalRecipient);
  else if (strstr(prog, "dovecot"))
    snprintf(d->message, sizeof d->message, "Running dovecot command, recipient is %s", OriginalRecipient);
  else if (strstr(prog, "forward"))
    snprintf(d->message, sizeof d->message, "Running forward command, recipient is %s", OriginalRecipient);

  child_pid = fork();
  saved_errno = errno;
  if (child_pid == -1) {
    // old: Unable to fork: %d.
    snprintf(msg, sizeof(msg), "Unable to fork: %d.", saved_errno);
    vexiterr(EXIT_DEFER, ERROR, msg, "Shell command failed, unable to fork, errno=%d %s", saved_errno, strerror(saved_errno));
  };
  if (child_pid == 0) {
    putenv("SHELL=/bin/sh");
    args[0] = "/bin/sh"; args[1] = "-c"; args[2] = prog; args[3] = NULL;
    sig_catch(SIGPIPE, SIG_DFL);
    execv(*args, args);
    // Rohan: don't log here. stdout is owned by the parent: printf("Unable to run /bin/sh: %d.", errno);
    // e.g. missing /bin/sh binary, not executable, ENOEXEC, EACCES, ENOMEM, too many open files, and so on
    _exit(120);
  };
  d->pid = child_pid; // ? for /bin/sh or the program it runs. Might be the latter
  // EINTR - a signal arrived to the parent while blocked in waitpid. Not a kill signal to the parent.
  //   e.g. kill -USR1 to the vdelivermail PID
  do {
    ret = waitpid(child_pid, &wstat, 0);
  } 
  while (ret < 0 && errno == EINTR);
  saved_errno = errno;

  // By this point the child process could've written error messages to stderr.

  if (ret < 0) {
    // e.g. ECHILD - pid is not waitable: already reaped, or SIGCHLD is SIG_IGN so the kernel auto-reaped it.
    vexiterr(EXIT_DEFER, ERROR, "", "Shell command failed, waitpid errno=%d (%s)", saved_errno, strerror(saved_errno));
  }

  if (WIFSIGNALED(wstat)) {
    d->has_signal = true;
    d->signal = WTERMSIG(wstat);
    // qmail-local says "Aack, child crashed. (#4.3.0)" we say, "Temporary system error. (#4.3.0)"
    vexiterr(EXIT_DEFER, ERROR, "", "Shell command failed, /bin/sh received signal");
  }

  if (!WIFEXITED(wstat)) {
    // impossible unless traced/stopped
    vexiterr(EXIT_DEFER, ERROR, "", "Shell command failed, /bin/sh terminated abnormally");
  }

  // e.g. 127 - bin/sh reports command not found
  xcode = WEXITSTATUS(wstat);

  if (xcode == 120) {
    // The child in v5.6 had "Unable to run /bin/sh: %d.", errno
    vexiterr(EXIT_DEFER, ERROR, "Unable to run /bin/sh", "Shell command failed, execv /bin/sh failed");
  }

  d->has_exit_status = true;
  d->code = xcode;
  d->success = xcode == 0 || xcode == 99;
  log_delivery(&gelf, d);
  d->in_progress = false;

  // See qmail-command (8) man page
  switch (xcode) {
    case 64:
    case 65:
    case 70:
    case 76:
    case 77:
    case 78:
    case 100:
    case 112:
      vexiterr(EXIT_BOUNCE, ERROR, NULL, "Shell command failed, hard fail");
      /*
        Hi. This is the qmail-send program at mail.example.com.
        I'm afraid I wasn't able to deliver your message to the following addresses.
        This is a permanent error; I've given up. Sorry it didn't work out.

        <user@example.com>:
        autoresponder: cannot open /path/to/file
      */
    case 99:
      vexiterr(EXIT_OK_STOP, INFO, NULL, "Shell command exited 99, vdelivermail skipping remaining instructions and exiting 99");
      // TODO: Consider returning -1 from fn instead.
      // See qmail-command man page. 99 means success, but prevent the remainder of .qmail being processed.
      // Calling vexit(99) here means that the remainder of .qmail-default will not be processed.
    case 0:
      break;
    default: // typically 111
      vexiterr(EXIT_DEFER, ERROR, NULL, "Shell command failed, soft fail");
  }

  return 0;
}


/* Append one physical line of a header to f's value, as raw bytes. If the
 * value runs out of room, store_header_value() keeps what fits and f is
 * marked truncated, so that its later lines are ignored; finish_field()
 * then decides what to log. */
static void field_append(struct header_field *f, const char *src) {
  if (!f->truncated && store_header_value(f->value, f->size, src)) {
    f->truncated = true;
  }
}


/* Has a header with line's name already been taken? Compares against the
 * names of the headers in the list, exactly as take_header() matches. */
static bool already_taken(const struct header_field *head, const char *line) {
  for (; head != NULL; head = head->next) {
    if (strncasecmp(line, head->name, strlen(head->name)) == 0) {
      return true;
    }
  }
  return false;
}


/* If line starts with name (case-insensitive, including its colon), claim
 * it: allocate a node, store the value, and point *current at the node for
 * the caller to link into its list and send continuation lines to. Returns
 * 1 on a name match, 0 otherwise. An empty name never matches. The caller
 * has already ruled out a repeat (already_taken). */
static int take_header(const char *line, const char *name, char *value,
                       size_t size, bool decode,
                       struct header_field **current) {
  struct header_field *f;
  size_t n = strlen(name);

  if (n == 0 || strncasecmp(line, name, n) != 0) {
    return 0;
  }
  f = calloc(1, sizeof(*f));
  if (f == NULL) {
    return 1;               /* out of memory: the caller reports it */
  }
  f->name = name;
  f->value = value;
  f->size = size;
  f->decode = decode;
  field_append(f, line + n);
  *current = f;
  return 1;
}


/* How much of an undecoded header to quote when it has to be dropped. */
#define HEADER_SAMPLE_MAX 80

/* Make a completed field safe to log. Until now it holds raw bytes.
 *
 * A field we don't decode is sanitised, and ends in "..." if it was cut.
 * A field we decode (Subject, From, To, CC) is decoded and sanitised,
 * ending in "..." if the decoded text doesn't fit. But if its raw value was
 * cut while being read, it is dropped instead: the cut may fall inside an
 * encoded-word, which would then be logged half decoded. The warning quotes
 * the start of the raw value, itself sanitised. */
static void finish_field(struct header_field *f) {
  char sample[HEADER_SAMPLE_MAX + 4];   /* + "..." + NUL */
  bool sample_cut;

  /* The repaired/truncated reports aren't needed here: U+FFFD and "..." are
   * visible in the logged value itself. */
  if (!f->decode) {
    sanitise_inplace(f->value, f->size, f->truncated, NULL, NULL);
    return;
  }
  if (!f->truncated) {
    decode_header_field(f->value, f->size, NULL, NULL);
    return;
  }

  sample[0] = '\0';
  sample_cut = store_header_value(sample, HEADER_SAMPLE_MAX + 1, f->value);
  sanitise_inplace(sample, sizeof(sample), sample_cut, NULL, NULL);

  f->value[0] = '\0';
  log_event(WARN, "%.*s header too long to log, omitted. Undecoded, it starts: %s",
            (int)(strlen(f->name) - 1), f->name, sample);   /* name without its colon */
}


/*
 * Read RFC 5322 headers from stdin until the blank separator line, populating
 * the fields in *h, for logging only. Rewinds stdin before reading (and may
 * defer if that seek fails). Subsequent consumers rewind themselves. Missing
 * or unrecognised headers leave their field as "".
 *
 * tracking_header names the site's own correlation header, e.g.
 * X-Submission-ID, and its value is stored in h->tracking_header.
 * Empty disables it.
 */
void extract_headers(message_headers_t *h, const char *tracking_header) {
  /* Longer than the largest field, so a field fills (and is marked
   * truncated) before a physical line is cut. */
  char line[2 * HEADER_VALUE_LONG_MAX];
  char tracking_needle[160];
  struct header_field *head = NULL;      /* headers taken so far, newest first */
  struct header_field *current = NULL;   /* the header receiving folded lines; NULL if none of ours */
  bool taken;

  memset(h, 0, sizeof(*h));

  /* take_header() matches on the name including its colon. */
  tracking_needle[0] = '\0';
  if (tracking_header != NULL && tracking_header[0] != '\0') {
    snprintf(tracking_needle, sizeof(tracking_needle), "%s:", tracking_header);
  }
  rewind_stdin();

  while (fgets(line, sizeof(line), stdin) != NULL) {

    // If fgets received more than sizeof(line)-1 bytes without a newline, 
    // fgets_truncated will continue reading up to the newline so that the 
    // next line will be processed normally.
    bool line_cut = fgets_truncated(line, sizeof(line), stdin);

    if (line[0] == '\n' || line[0] == '\r') {
      break;
    }

    if (line[0] == ' ' || line[0] == '\t') {
      if (current != NULL) {
        field_append(current, line);
      }
    } else {
      current = NULL;
      /* A repeat of a header already taken is ignored, continuation lines
       * included: first wins, even if the first was empty. */
      if (already_taken(head, line)) {
        continue;
      }
      /* decode: only Subject (unstructured) and the address fields (where
       * RFC 2047 permits an encoded-word inside the display-name phrase).
       * An encoded-word is not valid in the others, and decoding would only
       * let a sender smuggle text that renders differently from what was
       * transmitted.
       *
       * Tracking header last, so that a site which points it at a header we
       * already claim does not lose the standard field to it. */
      taken = (take_header(line, "Subject:", h->subject, sizeof(h->subject), true, &current)
          || take_header(line, "Message-ID:", h->message_id, sizeof(h->message_id), false, &current)
          || take_header(line, "From:", h->from, sizeof(h->from), true, &current)
          || take_header(line, "To:", h->to, sizeof(h->to), true, &current)
          || take_header(line, "CC:", h->cc, sizeof(h->cc), true, &current)
          || take_header(line, "Date:", h->date, sizeof(h->date), false, &current)
          || take_header(line, "X-Spam-Status:", h->x_spam_status, sizeof(h->x_spam_status), false, &current)
          || take_header(line, "Received:", h->received, sizeof(h->received), false, &current)
          || take_header(line, "Authentication-Results:", h->authentication_results, sizeof(h->authentication_results), false, &current)
          || take_header(line, "Sender:", h->sender, sizeof(h->sender), true, &current)
          || take_header(line, tracking_needle, h->tracking_header, sizeof(h->tracking_header), false, &current));
      if (current != NULL) {
        current->next = head;
        head = current;
      } else if (taken) {
        /* Matched, but take_header() couldn't allocate. Logging needs memory
         * too, but may still succeed. The name is one of ours, so ASCII. */
        log_event(ERROR, "out of memory: %.*s header not logged",
                  (int)strcspn(line, ":"), line);
      }
    }

    // handle delivered_to elsewhere, due to need for multiple occurrences.

    // consider X-Spam-Flag: YES

    // current->truncated is set during take_header and by field_append, if it can't fit the unfolded
    // string into the field length specified in message_headers_t in gelf.h.
    // We also must set current->truncated if any of the physical lines were too long.
    // This flag also prevents field_append from consuming any more physical lines until we reach the next header.
    if (line_cut && current != NULL) {
      current->truncated = true;
    }
  }

  /* Decode encoded-words now that every field is complete: adjacent
   * encoded-words lose the whitespace between them, and such a pair
   * regularly straddles a folded line, so this cannot be done per line. */
  while (head != NULL) {
    struct header_field *next = head->next;
    finish_field(head);
    free(head);
    head = next;
  }
}

/* Collect the value of every "Delivered-To:" header, in order, into
 * *delivered_to (a malloc'd NULL-terminated array built with array_push;
 * caller passes a NULL char** and frees the result with free_array()).
 * Values go through store_header_value() and sanitise_inplace(), so
 * they are trimmed and safe to log. Folded continuation lines are ignored. Stops at the blank
 * line ending the headers, or EOF. Most messages carry none, so this stays
 * cheap: rewind_stdin() plus one fgets() pass, no allocation at all unless a
 * Delivered-To line actually shows up.
 *
 * Deliberately re-scans stdin from scratch on every call rather than caching
 * the result anywhere: forward_to() and main() each want the list at a
 * different moment, and re-reading a few small header lines is cheaper than
 * threading a long-lived array through gelf.context with a free() on every
 * exit path. */
void collect_delivered_to(char ***delivered_to) {
  char loop_buf[1024]; // RFC 5322 allows 998 characters + CRLF
  char value[HEADER_VALUE_MAX];


  rewind_stdin();
  while (fgets(loop_buf, sizeof(loop_buf), stdin) != NULL) {
    /* A physical line longer than loop_buf: discard the rest, or it would be
     * read as a line of its own - padding followed by "Delivered-To: x"
     * would otherwise produce a Delivered-To header that isn't there. */
    bool line_cut = fgets_truncated(loop_buf, sizeof(loop_buf), stdin);

    if (strncasecmp(loop_buf, "Delivered-To:", 13) == 0) {
      bool cut;

      value[0] = '\0';
      cut = store_header_value(value, sizeof(value), loop_buf + 13);
      /* Only the "..." matters: a cut value can never equal an address. */
      sanitise_inplace(value, sizeof(value), cut || line_cut, NULL, NULL);
      array_push(delivered_to, value);
    } else if (*loop_buf == '\r' || *loop_buf == '\n') {
      /* end of headers */
      break;
    }
  }
}


/* Does any value in delivered_to (as collected by collect_delivered_to())
 * equal address, ignoring case? Pure array lookup, no stdin access.
 *
 * Return 1 if looping, 0 if not.
 */
int is_looping(char **delivered_to, const char *address) {
  int i;

  if (*address == '&') ++address;

  for (i = 0; delivered_to != NULL && delivered_to[i] != NULL; i++) {
    if (strcasecmp(delivered_to[i], address) == 0) {
      return (1);
    }
  }

  return (0);
}


/* Append the collected Delivered-To values to buf for the loop-bounce
 * full_message, one "Delivered-To: <value>" per line. Header order is newest
 * first, since each delivery agent prepends its line, so walk the array
 * backwards to print them in chronological order. sanitise_inplace()
 * has already replaced any CR/LF in the values, so each stays on one line.
 *
 * TRUNCATION_RESERVE bytes are held back so that, if the list doesn't fit, a
 * final "...", blank line and "N more omitted" always do. An entry that doesn't fit is
 * dropped whole rather than cut. No-op if delivered_to is NULL/empty. */
#define TRUNCATION_RESERVE 40
static void append_delivered_to(char *buf, size_t bufsize, char **delivered_to) {
  size_t used;
  size_t limit;
  int last;
  int i;
  int r;

  if (delivered_to == NULL || delivered_to[0] == NULL) return;
  if (bufsize <= TRUNCATION_RESERVE) return;
  limit = bufsize - TRUNCATION_RESERVE;

  used = strlen(buf);
  if (used >= limit) return;
  r = snprintf(buf + used, limit - used, "\nDelivered-To lines seen, in chronological order:\n");
  if (r < 0 || (size_t)r >= limit - used) {
    buf[used] = '\0';
    return;
  }
  used += (size_t)r;

  last = array_count(delivered_to) - 1;
  for (i = last; i >= 0; i--) {
    r = snprintf(buf + used, limit - used, "\nDelivered-To: %s", delivered_to[i]);
    if (r < 0 || (size_t)r >= limit - used) {
      buf[used] = '\0';  /* snprintf leaves a partial entry; drop it */
      snprintf(buf + used, bufsize - used, "\n...\n\n%d more omitted", i + 1);
      return;
    }
    used += (size_t)r;
  }
}


#ifdef SPAMASSASSIN
/* Check for a spam message
 *  * This is done by checking for a matching line
 *   * in the email headers for X-Spam-Level: which
 *    * we put in each spam email
 *     *
 *      * Return 2 if heavy spam
 *      * Return 1 if light spam
 *       * Return 0 if not spam
 *        * Return -1 on error
 *         */
int is_spam(char *spambuf, int len, int *in_headers) {
  int i, j, k;
  int found;
  int spam = 0;
  int rowlen;

  for (i = 0, j = 0; i < len; ++i) {
    /* found a line */
    if (spambuf[i] == '\n') {
      /* check for blank line, end of headers */
      for (k = j, found = 0; k < i; ++k) {
        switch (spambuf[k]) {
          /* skip blank spaces and new lines */
          case ' ':
          case '\n':
          case '\t':
          case '\r':
            break;

          /* found a non blank, so we are still
           * in the headers
           */
          default:
            /* set the found non blank char flag */
            found = 1;
            break;
        }
      }
      if (found == 0) {
        if (in_headers) *in_headers = 0;
        return (spam);
      }

      /* still in the headers check for spam header */
      rowlen = i - j;
      if (spam == 0 && rowlen == 16 &&
          strncmp(&spambuf[j], "X-Spam-Flag: YES", 16) == 0)
        spam = 1;
#ifdef SPAM_THRESHOLD
      else if (rowlen > 14 + SPAM_THRESHOLD &&
               strncmp(&spambuf[j], "X-Spam-Level: ", 14) == 0)
        return (2);
#endif

      j = i + 1;
    }
  }
  return (0);
}
#endif


/* Hand the message to maildrop, which files it itself; fdcopy()'s caller then discards the
 * tmp file we had been writing.
 *
 * WARNING: This feature has had minimal testing. In all of vpopmail's history its maildrop
 * feature has never been capable of handling valias lines (or user-not-found catchall instructions)
 * that specify a maildir. It only worked if it coincidentally matched the user's home directory.
 * Perhaps admins would be better served by running maildrop from within defaultdelivery instead.
 *
 * fdcopy()'s own extra_headers went to write_fd,
 * not to stdin, so preline is what puts them in front of the message here.
 *
 * read_fd is the message to hand over, and must be passed rather than left to inheritance.
 * For an ordinary delivery it is already fd 0 and the dup2 below is a no-op. For a quota
 * warning it is the open .quotawarn.msg, while fd 0 still holds the incoming message that a
 * previous maildrop run consumed to EOF -- inheriting fd 0 there fed maildrop nothing and
 * lost the warning entirely. When SpamAssassin ran, fdcopy() has replaced fd 0 with spamc's
 * output and read_fd is 0, so the dup2 is skipped and maildrop reads the filtered message.
 *
 * Don't rewind: fdcopy() already rewound stdin where that was right, and doing it again would
 * be wrong in the spamc case.
 *
 * Every failure exits, so the caller needs no error path. Non-zero from maildrop defers rather
 * than bounces: maildrop signals temporary failure with EX_TEMPFAIL 75.
 */
void run_maildrop(int read_fd) {
  char *args[3];
  pid_t pid;
  int wstat, ret, xcode, saved_errno;

  #ifndef MAILDROP_PROG
  #define MAILDROP_PROG NULL
  #endif

  // preline prepends the Delivered-To and Return-Path lines maildrop expects, taken from DTLINE and RPLINE.
  args[0] = QMAILDIR "bin/preline"; /* QMAILDIR carries its own trailing slash */
  args[1] = MAILDROP_PROG;
  args[2] = NULL;

  pid = fork();
  saved_errno = errno;
  if (pid == -1) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, unable to fork, errno=%d %s",
             saved_errno, strerror(saved_errno));
  }
  if (pid == 0) {
    if (read_fd != 0 && dup2(read_fd, 0) == -1) _exit(121);
    sig_catch(SIGPIPE, SIG_DFL);
    execv(args[0], args);
    /* Don't report errors to stdout here: stdout belongs to the parent, which sees 120 via waitpid. */
    _exit(120);
  }

  do {
    ret = waitpid(pid, &wstat, 0);
  } while (ret < 0 && errno == EINTR);
  saved_errno = errno;

  if (ret < 0) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, waitpid errno=%d (%s)",
             saved_errno, strerror(saved_errno));
  }
  if (WIFSIGNALED(wstat)) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, received signal %d", WTERMSIG(wstat));
  }
  if (!WIFEXITED(wstat)) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, terminated abnormally");
  }

  xcode = WEXITSTATUS(wstat);
  if (xcode == 120) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, could not execute %s", args[0]);
  }
  if (xcode == 121) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, could not place the message on stdin");
  }
  if (xcode != 0) {
    vexiterr(EXIT_DEFER, ERROR, "", "maildrop failed, exited %d", xcode);
  }
}


/**
 * @returns if delivery worked
 * @retval 0 message was delivered as is
 * @retval -1 error
 *
 * delete_mail / move_mail / in_headers may be NULL (e.g. inject / stdout);
 * only set when non-NULL.
 * local: 1 means delivering to a Maildir (enable SA/maildrop paths)
 * spamc_user: identity for spamc -u. Empty string skips spamc
 */
/* effective_flags is the resolved NO_MAILDROP/NO_SPAMASSASSIN/DELETE_SPAM policy
 * (a vqpasswd pw_flags value -- see vlimits_setflags()/calc_effective_flags())
 * for whoever actually owns the delivery this call is for. The caller is
 * responsible for resolving it correctly (confirmed owner vs. not); this
 * function just applies it and never touches TheDomain/vauth_getpw itself.
 * Ignored when local != 1.
 */
static int fdcopy(int write_fd, int read_fd, const char *extra_headers,
                  size_t headerlen, const char *spamc_user, int *delete_mail,
                  int *move_mail, int *in_headers, int local, gid_t effective_flags) {
  ssize_t file_count;
#ifndef SPAMASSASSIN
  (void)local; // only used for spamc
#endif
#ifdef SPAMASSASSIN
  pid_t pid;
  int pim[2];
#endif

  /* Quota warnings pass a different fd. We'd use lseek if we needed to rewind those. */
  if (read_fd == 0) {
    rewind_stdin();
  }

  /* write extra_headers (Return-Path, Delivered-To, ...) ahead of the message */
  if (headerlen > 0) {
    if (write(write_fd, extra_headers, headerlen) != (ssize_t)headerlen) return -1;
  }

  /* fork the SpamAssassin client - based on work by Alex Dupre */
#ifdef SPAMASSASSIN
  if (local == 1 && spamc_user && *spamc_user && !(effective_flags & NO_SPAMASSASSIN) && !pipe(pim)) {
    pid = fork();
    switch (pid) {
      case -1:
        close(pim[0]);
        close(pim[1]);
        break;
      case 0:
        close(pim[0]);
        dup2(pim[1], 1);
        close(pim[1]);
        if (execl(SPAMC_PROG, SPAMC_PROG, "-f", "-u", spamc_user, (char *)NULL) == -1) {
          // spamc couldn't run: pass the message through unfiltered.
          while ((file_count = read(0, msgbuf, sizeof(msgbuf))) > 0) {
            if (write(1, msgbuf, file_count) != file_count) _exit(1);
          }
          _exit(0);
        }
    }
    close(pim[1]);
    dup2(pim[0], 0);
    close(pim[0]);
  }
#endif

#ifdef MAILDROP
  // WARNING: This delivery pathway ignores the message file we just created on disk and
  // then maildrop obtains the message content from stdin. It determines the destination
  // by parsing EXT and HOST all over again. valias lines that specify othe maildir paths
  // are disregarded.
  if (local == 1 && !(effective_flags & NO_MAILDROP)) {
    run_maildrop(read_fd);
    if (delete_mail) *delete_mail = 1;
    return (0);
  }
#endif

  /* read it in chunks and write it to the new file */
  while ((file_count = read(read_fd, msgbuf, sizeof(msgbuf))) > 0) {
#ifdef SPAMASSASSIN
    if (local == 1 && in_headers && *in_headers == 1
#if defined(SPAM_THRESHOLD) || defined(SPAM_JUNKFOLDER)
    ) {
#else
        && (effective_flags & DELETE_SPAM)) {
#endif
      switch (is_spam(msgbuf, file_count, in_headers)) {
        case 2:
#ifdef SPAM_THRESHOLD
          if (delete_mail) *delete_mail = 1;
          return (0);
#endif
        case 1:
          if (effective_flags & DELETE_SPAM) {
            if (delete_mail) *delete_mail = 1;
            return (0);
          }
#ifdef SPAM_JUNKFOLDER
          if (move_mail) *move_mail = 1;
#endif
      }
    }
#endif
    if (write(write_fd, msgbuf, file_count) == -1) return -1;
  }
#ifdef SPAMASSASSIN
  /* No body */
  if (in_headers && *in_headers == 1 && delete_mail) *delete_mail = 1;
#endif
#if !defined(SPAMASSASSIN) && !defined(MAILDROP)
  (void)delete_mail;
  (void)spamc_user;
  (void)effective_flags;
#endif
#ifndef SPAM_JUNKFOLDER
  (void)move_mail;
#endif
#ifndef SPAMASSASSIN
  (void)in_headers;
#endif

  return 0;
}


/* Is this path a Maildir++ .Trash folder? Tolerates a trailing slash and a relative path,
 * since a delivery target arrives spelled however the instruction wrote it. */
static bool is_trash_folder(const char *path) {
  size_t len, i;

  if (path == NULL) return false;
  len = strlen(path);
  while (len > 1 && path[len - 1] == '/') len--; /* ignore trailing slashes */
  i = len;
  while (i > 0 && path[i - 1] != '/') i--;       /* i now indexes the last component */
  return (len - i) == 6 && strncmp(path + i, ".Trash", 6) == 0;
}


/* save email in maildir, starting with extra_headers and then msgsize bytes
 * read from read_fd.
 *
 * final_message_size_out, when not NULL, receives the size of the message file once it has
 * been successfully generated on disk in the maildir's tmp/ -- after extra headers, and after
 * anything SpamAssassin or maildrop did to it, so it is not the size of the incoming message.
 * Set to 0 first, and left there whenever no complete file was produced: a write that failed
 * part-way (EDQUOT included), a close that failed, or a stdout delivery that never opens one.
 * It is reported even if the file is then discarded rather than filed.
 *
 * quota_root is the directory whose maildirsize records this delivery -- the maildir
 * itself, or its parent when maildir is a Maildir++ folder. See calc_quota_root().
 *
 * If quota is non-empty, it is the Maildir++ allocation limit (typically
 * the owner's pw_shell). After a successful delivery, maildir_addquota records
 * this message as a consumption delta and, if maildirsize is new, writes
 * that limit as the file's first line. Empty/NULL skips both.
 *
 * For spamc_user, empty string means don't attempt spamc at all.
 *
 * effective_flags is the resolved NO_MAILDROP/NO_SPAMASSASSIN/DELETE_SPAM policy
 * for spamc_user's actual owner (see fdcopy()) -- the caller must resolve
 * this correctly, since a maildir delivery may not belong to spamc_user at all.
 *
 * Return: 0 = success, -1 = over quota [i.e. OS enforced quota], -2 = system failure, -3 = looping
 */
int deliver_to_maildir(const char *maildir, const char *quota_root,
                       const char *extra_headers,
                       int read_fd, const char *quota, const char *spamc_user,
                       gid_t effective_flags, size_t *final_message_size_out) {
#ifdef HOST_NAME_MAX
  char hostname[HOST_NAME_MAX];
#else
  char hostname[256];
#endif
  long unsigned pid, tm;
  /* The previous delivery's time, see below. */
  static long unsigned last_tm = 0;
  char local_file_tmp[PATH_MAX];
  char local_file_new[PATH_MAX];
  size_t headerlen;
  struct stat sb;
  size_t msgsize;
  int write_fd;
  int delete_mail = 0;
  int move_mail = 0;
  int in_headers = 1; // only used by SpamAssassin code
#ifdef SPAM_JUNKFOLDER
  struct stat mystatbuf;
  char dir[PATH_MAX];
#endif

  headerlen = strlen(extra_headers);
  if (final_message_size_out) *final_message_size_out = 0;

  if (DeliverToStdout) {
    // Setting local=0 here, to avoid maildrop from doing a real delivery. Consider enabling spamc only, for this pathway.
    if (fdcopy(1, read_fd, extra_headers, headerlen,
               spamc_user, NULL, NULL, NULL, 0, 0) < 0) {
      log_event(ERROR, "echo to stdout failed");
      return -2;
    } else {
      /* Email sent to STDOUT */
      return 0;
    }
  }

  /* Format the email file name */
  /* we get the whole hostname, even though we only use 32 chars of it */
  gethostname(hostname, sizeof(hostname));
  pid = (long unsigned)getpid();
  tm = (long unsigned)time((time_t *)NULL);
  /* time.pid.host is only unique for one delivery per process per second, and this process can
   * make several: valias lines, or a message followed by its quota warning into the same
   * maildir. Advance the time part past the previous delivery's, so each name differs. Readers
   * mustn't extract information from the name, so it doesn't matter that it runs ahead. 
   * The last sentence was inspired by https://cr.yp.to/proto/maildir.html
  */
  if (tm <= last_tm) tm = last_tm + 1;
  last_tm = tm;
  if ((size_t)snprintf(local_file_tmp, sizeof(local_file_tmp), "%s/tmp/%lu.%lu.%.32s",
                       maildir, tm, pid, hostname) >= sizeof(local_file_tmp)) {
    // A truncated name could land outside tmp/, or clash with another message.
    log_event(ERROR, "maildir path, at %zu bytes, is too long to deliver into %s", strlen(maildir), maildir);
    return -2;
  }

  /* open the new email file */
  if ((write_fd = open(local_file_tmp, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) ==
      -1) {
    if (errno == EDQUOT) return -1;
    log_event(ERROR,"can not open new email file errno=%d file=%s", errno, local_file_tmp);
    return (-2);
  }

  if (fdcopy(write_fd, read_fd, extra_headers, headerlen,
             spamc_user, &delete_mail, &move_mail,
             &in_headers, 1, effective_flags) < 0) {
    /* Did the write fail because we were over quota? */
    if (errno == EDQUOT) {
      close(write_fd);
      unlink(local_file_tmp);
      return -1;
    } else {
      log_event(ERROR,"write failed errno = %d", errno);
      close(write_fd);
      unlink(local_file_tmp);
      return -2;
    }
  } 

  /* completed write to tmp directory, now move it into the new directory */

  /* sync the data to disk and close the file */
  errno = 0;
  if (
#ifdef FILE_SYNC
#ifdef HAVE_FDATASYNC
      fdatasync(write_fd) == 0 &&
#else
      fsync(write_fd) == 0 &&
#endif
#endif
      close(write_fd) == 0) {

    if (stat(local_file_tmp, &sb) == -1) {
      delete_mail = 1;
    } else if (final_message_size_out) {
      /* The file exists and is complete, so report its size whatever becomes of it next --
       * including the discard just below, where SA or maildrop generated a perfectly good
       * file in tmp/ and then declined to have it filed. */
      *final_message_size_out = sb.st_size;
    }

    if (delete_mail == 1) { // only relevant to SA or maildrop
      if (unlink(local_file_tmp) != 0) {
        log_event(ERROR, "unlink failed %s errno = %d\n", local_file_tmp, errno);
        // Rohan: removed return (errno); This is a success path because a message 
        // landed in `tmp`, but SA/maildrop don't want it delivered, e.g. because it's spam.
      }
      return (0);
    }

    msgsize = sb.st_size;
    if ((size_t)snprintf(local_file_new, sizeof(local_file_new),
                         "%s/new/%lu.%lu.%.32s,S=%lu", maildir, tm, pid, hostname,
                         (long unsigned)msgsize) >= sizeof(local_file_new)) {
      log_event(ERROR, "maildir path, at %zu bytes, is too long to deliver into %s", strlen(maildir), maildir);
      unlink(local_file_tmp);
      return -2;
    }

    /* Maildir++ leaves .Trash out of the quota total -- countsubdir() in maildirquota.c skips
     * it when rebuilding the PARENT's maildirsize -- so anything we recorded for a delivery
     * into a Trash folder would be erased at the next rebuild. Don't record it in the first
     * place.
     *
     * That reasoning only holds while .Trash is a folder of some other maildir. A maildir that
     * merely happens to be named .Trash (its parent is not a maildir, so calc_quota_root() left
     * it as its own quota root) is rebuilt from its own cur/new like anything else, and must be
     * recorded normally. quota_root tells the two apart: it is the parent in the first case and
     * the destination itself in the second. Comparing with is_trash_folder() rather than strcmp
     * because maildir is the instruction as written -- often relative, often with a trailing
     * slash -- while quota_root is absolute and canonical. */
    const bool record_consumption = quota && *quota && strcmp(quota, "NOQUOTA") != 0
                                    && !(is_trash_folder(maildir) && !is_trash_folder(quota_root));

    /* Say so when a Trash folder is what suppressed it. The other two reasons -- no quota, or
     * NOQUOTA -- are the account's ordinary configuration and are reported elsewhere. */
    if (!record_consumption && is_trash_folder(maildir)) {
      log_event(DEBUG, "delivery into %s: Maildir++ leaves .Trash out of the quota total, so "
                "no consumption is recorded against %s/maildirsize", maildir, quota_root);
    }

    /* if this succeeds link the file to the new directory */
#ifdef SPAM_JUNKFOLDER
    if (move_mail == 1) {
      if ((size_t)snprintf(dir, sizeof(dir), "%s/.Junk", maildir) >= sizeof(dir)) {
        log_event(ERROR, "maildir path, at %zu bytes, is too long to deliver into %s", strlen(maildir), maildir);
        unlink(local_file_tmp);
        return -2;
      }
      // Create .Junk and its cur/new/tmp by full path, rather than chdir()ing into it.
      // EEXIST is fine: a concurrent delivery may have just made it.
      static const char *const junk_subdirs[] = { "", "/cur", "/new", "/tmp" };
      if (stat(dir, &mystatbuf) == -1) {
        for (size_t j = 0; j < sizeof junk_subdirs / sizeof junk_subdirs[0]; j++) {
          char subdir[PATH_MAX];
          if ((size_t)snprintf(subdir, sizeof subdir, "%s%s", dir, junk_subdirs[j]) >= sizeof subdir
              || (mkdir(subdir, VPOPMAIL_DIR_MODE) == -1 && errno != EEXIST)) {
            log_event(ERROR, "couldn't create Junk folder %s: %s", subdir, strerror(errno));
            unlink(local_file_tmp);
            return (-2);
          }
        }
      }
      if ((size_t)snprintf(local_file_new, sizeof(local_file_new),
                           "%s/.Junk/new/%lu.%lu.%.32s,S=%lu", maildir, tm, pid, hostname,
                           (long unsigned)msgsize) >= sizeof(local_file_new)) {
        log_event(ERROR, "maildir path, at %zu bytes, is too long to deliver into %s", strlen(maildir), maildir);
        unlink(local_file_tmp);
        return -2;
      }
    }
#else
    (void)move_mail;
#endif
    if (link(local_file_tmp, local_file_new) == 0) {
      /* file was successfully delivered, remove temp file */
      if (unlink(local_file_tmp) != 0) {
        /* not a critical error */
        log_event(ERROR, "unlink failed %s errno = %d\n", local_file_tmp, errno); // then we return 0 below
      }
      if (record_consumption) {
        maildir_addquota(quota_root, -1, format_maildirquota(quota), msgsize, 1);
      }
      return 0;
    } 
    else {
      /* link() failed. Some filesystems don't support hard links and it's hard to predict what
       * they will return for errno, so other than EEXIST, we fallback to rename() and don't emit
       * a log message. */
      int link_errno = errno;
      if (link_errno == EEXIST) {
        /* rename() would silently replace the message already there.
         * Linux man page link(2), BUGS: on NFS "the return code may be wrong in case the NFS
         * server performs the link creation and dies before it can say so", so the retry may
         * deliver a duplicate, as qmail-local would. */
        log_event(ERROR, "link failed, %s already exists", local_file_new);
        unlink(local_file_tmp); /* remove temp file */
        return -2;
      }
      if (rename(local_file_tmp, local_file_new) == 0) {
        /* file was successfully delivered */
        if (record_consumption)
          maildir_addquota(quota_root, -1, format_maildirquota(quota), msgsize, 1);
        return 0;
      }
      /* even rename failed, time to give up */
      log_event(ERROR, "link failed (%s) and then rename failed (%s), %s -> %s",
                strerror(link_errno), strerror(errno), local_file_tmp, local_file_new);
      unlink(local_file_tmp); /* remove temp file */
      return -2;
    }
  }

  /* return failure (sync/close failed, message NOT delivered) */
  return -2;
}


/* Forks qmail-inject. Child PID is stored in *pid_out; parent write end of the
 * pipe in *write_fd_out. Pipe/fork failure calls vexiterr and does not return. */
static void qmail_inject_open(char *address, pid_t *pid_out, int *write_fd_out) {
  int pim[2];
  pid_t pid;
  static char *binqqargs[4];
  char msg[HEADER_VALUE_MAX];
  int saved_errno;

  if (pipe(pim) == -1) {
    vexiterr(EXIT_DEFER, ERROR, "system error, can't open qmail-inject", // v5.6 msg
     "Forwarding failed, unable to obtain pipe: errno=%d %s", errno, strerror(errno));
  }

  pid = fork();
  saved_errno = errno;
  if (pid == -1) {
    close(pim[0]);
    close(pim[1]);
    snprintf(msg, sizeof(msg), "Unable to fork: %d.\nsystem error, can't open qmail-inject", saved_errno); // in v5.6 this was logged to qmail-send
    vexiterr(EXIT_DEFER, ERROR,msg,"Forwarding failed, unable to fork, errno=%d %s",saved_errno,strerror(saved_errno));
  }
  if (pid == 0) {
    close(pim[1]);
    if (vfd_move(0, pim[0]) == -1) _exit(120); // formerly -1, which waitpid would receive as 255
    binqqargs[0] = QMAILINJECT;
    binqqargs[1] = "--";
    binqqargs[2] = address;
    execv(*binqqargs, binqqargs);
    // Don't log here: stdout is owned by the parent. inject_mail sees 120 via waitpid.
    _exit(120); // _exit avoids stdio flush and atexit
  }
  *pid_out = pid;
  *write_fd_out = pim[1];
  close(pim[0]);
}


/* Refuse to forward to an address already listed in Delivered-To.
 * Local cycles (A->B->A) are caught here at B. For an off-box target this
 * avoids sending a second copy to someone who already handled the message;
 * qmail-local does not check the forward target;
 * bouncexf only looks for this hop's line.
 * Without this function, a local cycle would still bounce one hop later, at A,
 * via check_for_mail_loop() in main(); an off-box duplicate would not. */
void prevent_mail_forwarding_loop(char *address) {
  char **delivered_to = NULL;

  collect_delivered_to(&delivered_to);
  if (is_looping(delivered_to, address) == 1) {
    snprintf(
     gelf.context.exit_full_message, sizeof(gelf.context.exit_full_message),
     "Refusing to forward from %s to %s, as the incoming message already has a Delivered-To"
     " header containing %s. Could be caused by a local valias/.qmail cycle."
     " For an off-box target this avoids sending a second copy to a mailbox that already handled this message.",
     DealiasedRecipient, address, address
    );
    append_delivered_to(gelf.context.exit_full_message, sizeof(gelf.context.exit_full_message), delivered_to);
    free_array(delivered_to);
    gelf.context.is_looping = true;
    vexiterr(EXIT_BOUNCE, ERROR, "mail is looping", "$M, won't forward to %s", address);
  }
  free_array(delivered_to);
}


// address - without the "&" prefix
void inject_mail(char *address, const char *log_source) {
  pid_t inject_pid = 0;
  int fdm;
  int wstat;
  int xcode;
  char extra_headers[HEADERS_SIZE] = "";
  delivery_log_t *d = &gelf.context.delivery;
  int saved_errno;
  int ret;

  memset(d, 0, sizeof *d);
  d->in_progress = true;
  snprintf(d->instruction, sizeof d->instruction, "&%s", address);
  d->source = log_source;
  d->method = "forward";

  if (strcmp(log_source,"catchall")==0) {
    snprintf(d->message, sizeof d->message, "Forwarding to catch-all address %s", address);
  }
  else {
    snprintf(d->message, sizeof d->message, "Forwarding to %s", address);
  }
  
  
  char msg[HEADER_VALUE_MAX];

  // Bounces with, "Sorry, I wasn't able to deliver this message. (#5.3.0)"
  // v5.6 had "qmail-inject: fatal: unable to parse address: <addr>\n"
  // then vexiterr(100, "system error calling qmail-inject")
  validate_forwarding_address(address,0);

  // Note: We could at this point disallow forwarding to DealiasedRecipient or OriginalRecipient,
  // but when there are multiple valias lines, this could cause vdelivermail to bounce early.
  // So enabling this check could reduce the amount of successful forwarding.
  // Best let the problem be detected downstream. Also note that qmail-local has no such early test.

  prevent_mail_forwarding_loop(address);

  qmail_inject_open(address, &inject_pid, &fdm);
  d->pid = inject_pid;

  /* The forwarded copy records the address that forwarded it, i.e. us.
   * 5.6 reconstructed this by string arithmetic on DTLINE, stripping the
   * virtualdomains prefix off "example.com-bob@example.com". That produced the
   * as-received domain, whereas main() checks for the dealiased one, so a loop
   * arriving via an alias domain matched neither. DealiasedRecipient is the same
   * string in both places. Don't set X-Original-To here. */

  add_header(extra_headers, sizeof extra_headers, "Return-Path",
             angle_bracketed(ReturnPath));
  add_header(extra_headers, sizeof extra_headers, "Delivered-To",
             DealiasedRecipient);

  if (fdcopy(fdm, 0, extra_headers, strlen(extra_headers), address, NULL, NULL, NULL, 0, 0) < 0) {
    saved_errno = errno; // captured before close/waitpid clobber it
    close(fdm);
    do {
      ret = waitpid(inject_pid, &wstat, 0);
    }
    while (ret < 0 && errno == EINTR);

    if (ret >= 0 && WIFSIGNALED(wstat)) {
      d->has_signal = true;
      d->signal = WTERMSIG(wstat);
      vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject",
               "Forwarding failed, couldn't write to qmail-inject, errno=%d (%s), qmail-inject received signal",
               saved_errno, strerror(saved_errno));
    }
    if (ret >= 0 && WIFEXITED(wstat)) {
      int wcode = WEXITSTATUS(wstat);
      if (wcode != 120) {
        d->has_exit_status = true;
        d->code = wcode;
      }
      if (wcode == 120) {
        // inject never ran: vfd_move or execv failed in the child, causing the EPIPE.
        vexiterr(EXIT_DEFER, ERROR, "Unable to launch qmail-inject.", // same message as v5.6
                 "Forwarding failed, $M: execv %s failed (write errno=%d)",
                 QMAILINJECT, saved_errno);
      }
      // If inject already decided to bounce (e.g. bad address -> EPIPE on our write),
      // honour that rather than deferring: the message will never succeed.
      if (wcode == 100) {
        vexiterr(EXIT_BOUNCE, ERROR, "system error calling qmail-inject", // v5.6 msg
          "Forwarding failed, couldn't write to qmail-inject, errno=%d (%s), qmail-inject wants us to bounce",
          saved_errno, strerror(saved_errno));
      }
    }
    snprintf(msg, sizeof(msg),
      "Write to qmail-inject failed: %d\nsystem error calling qmail-inject",
      saved_errno); // as per v5.6
    vexiterr(EXIT_DEFER, ERROR, msg, "Forwarding failed, couldn't write to qmail-inject, errno=%d (%s)",
      saved_errno, strerror(saved_errno));
  }
  close(fdm);

  // EINTR - a signal arrived to the parent while blocked in waitpid. Not a kill signal to the parent.
  do {
    ret = waitpid(inject_pid, &wstat, 0);
  }
  while (ret < 0 && errno == EINTR);
  saved_errno = errno;

  if (ret < 0) {
    vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject", // v5.6 msg
             "Forwarding failed, waitpid errno=%d (%s)", saved_errno, strerror(saved_errno));
  }

  if (WIFSIGNALED(wstat)) {
    d->has_signal = true;
    d->signal = WTERMSIG(wstat);
    vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject",
     "Forwarding failed, qmail-inject received signal");
  }

  if (!WIFEXITED(wstat)) {
    vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject", "Forwarding failed, $M"); // v5.6 msg
  };

  xcode = WEXITSTATUS(wstat);
  if (xcode == 120) {
    vexiterr(EXIT_DEFER, ERROR, "Unable to launch qmail-inject.", // same message as v5.6
             "Forwarding failed, $M: execv %s failed", QMAILINJECT);
  };
  d->has_exit_status = true;
  d->code = xcode; // expect 0,100,111
  if (xcode == 100) {
    // qmail-inject has already printed to stderr
    // e.g. qmail-inject: fatal: unable to parse address: <addr>
    vexiterr(EXIT_BOUNCE, ERROR, "system error calling qmail-inject", // v5.6 msg, consider passing NULL
     "Forwarding failed, qmail-inject wants us to bounce");
  }
  if (xcode == 111) {
    // qmail-inject has already printed to stderr. e.g. Permissions issue like:
    // qmail-inject: fatal: qq trouble creating files in queue (#4.3.0)
    vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject", // v5.6 msg, consider passing NULL
     "Forwarding failed, qmail-inject wants us to defer");
  }
  if (xcode != 0) {
    vexiterr(EXIT_DEFER, ERROR, "system error calling qmail-inject", // v5.6 msg
     "Forwarding failed, unexpected exit code from qmail-inject");
  }
  
  d->success = true;
  log_delivery(&gelf, d);
  d->in_progress = false;
}


// resolves the destination purely from qmail's envelope environment
//1:6:maildrop/maildroprc.v2
// import EXT
// import HOST
// VPOPMAILDIR="/home/vpopmail"
// VHOME=`$VPOPMAILDIR/bin/vuserinfo -d $EXT@$HOST`
// DOMDIR=`$VPOPMAILDIR/bin/vdominfo -d $HOST`
// NOEXT=`echo $EXT | awk -F- '{ print $1}'`
// and ends with `to $VHOME/Maildir/`


// Returns true if the warning was sent in the last 24 hours.
// exception handling: does not exit. returns true and logs. The warning probably wouldn't succeed anyway.
bool quota_warning_sent_recently(const char *dir) {
  time_t tm;
  struct stat sb;
  char quotawarnmsg[PATH_MAX];
  if ((size_t)snprintf(quotawarnmsg, sizeof(quotawarnmsg), "%s/quotawarn", dir) >= sizeof(quotawarnmsg)) {
    log_event(ERROR, "The path to the quotawarn timestamp file is too long: %s", dir);
    return true;
  }
  time(&tm);
  return stat(quotawarnmsg, &sb) == 0 && ((sb.st_mtime + 86400) > tm);
  // TODO: log exotic errors
}


// Returns true if a readable .quotawarn.msg exists, looking in domain_dir (skipped if empty), then the
// global domains dir. Its presence is what enables quota warnings. template_path_out must point to at least PATH_MAX bytes.
bool detect_quotawarn_template(const char *domain_dir, char *template_path_out) {
  int fd;
  int r;

  r = snprintf(template_path_out, PATH_MAX, "%s/.quotawarn.msg", domain_dir);
  if (domain_dir[0] != '\0' && (size_t)r < PATH_MAX && (fd = open(template_path_out, O_RDONLY)) >= 0) {
    // Consider also calling fstat(fd) to test for S_ISREG to rule out directories.
    close(fd);
    return true;
  }
  snprintf(template_path_out, PATH_MAX, "%s/.quotawarn.msg", DOMAINS_TREE);
  if ((fd = open(template_path_out, O_RDONLY)) >= 0) {
    close(fd);
    return true;
  }
  template_path_out[0] = '\0';
  return false;
}


/*
 * Deliver a quota warning message
 *
 * quota_string - used to update maildirsize.
 *   This is the recipient maildir's quota allocation, never the domain's quota limit.
 *   In practice its allocation component is not updated here: doaddquota() writes line 1 only when
 *   it has to create the file, and it won't have to -- either an earlier user_over_maildirquota()
 *   already built it, or the vusage daemon is answering, in which case maildir_addquota() returns
 *   without touching the file at all.
 *   However, if we didn't pass the quota arg to deliver_to_maildir(), it wouldn't update the consumption component.
 *   If callers wish to skip it, they can pass "" (but not NULL).
 * template_path - the .quotawarn.msg found by detect_quotawarn_template().
 * reason - why the warning is being sent, for the log only; every reason uses the same template.
 *
 * Return 0 on success
 * Return less than zero on failure
 *
 * -1 = user is over quota [i.e. not virtual quota, this is only when errno == EDQUOT]
 * -2 = system failure
 * -3 = mail is looping
 */
int deliver_quota_warning(const char *dir, const char *template_path, const char *reason, const char *quota_string,
 const char *quota_warning_user) {
  int fd, read_fd;
  int err;
  char quotawarnmsg[PATH_MAX];
  char extra_headers[HEADERS_SIZE] = "";
  const char *date;

  // We use a local delivery_log here, as our caller, manage_deliver_to_mail, is using the 
  // gelf.context.delivery to track its own in-progress delivery.
  // vexiterr are only possible during deliver_to_maildir within its maildrop delivery path,
  // but at least those will trigger a delivery log describing the outcome of our caller's primary delivery attempt.
  delivery_log_t delivery_log;
  delivery_log_t *d = &delivery_log;

  memset(d, 0, sizeof *d);
  // don't set "source" or "instruction" - the delivery is not the result of a user-configured delivery instruction.  
  // Won't set maildir_initial_bytes, it'd be maildir_initial_bytes (from the primary delivery) + size by now.
  // Not setting other maildir_quota fields, we didn't check quota again for the sake of this warning message.
  // Not setting maildir_nearly_full again, that was set for the primary delivery.
  d->in_progress = true; // though there is no vexiterr checking it
  d->method = "maildir";
  snprintf(d->maildir_path, sizeof d->maildir_path, "%s", dir);

  if (!quota_warning_user || quota_warning_user[0] == '\0') {
    snprintf(d->message, sizeof d->message, "Notifying recipient, writing to %s, %s", dir, reason);
  }
  else { // calc_maildir_constraints documents a rare situation where quota_warning_user is erroneous, so we log dir as well.
    snprintf(d->message, sizeof d->message, "Notifying %s, writing to %s, %s", quota_warning_user, dir, reason);
  }

  // Touch the quotawarn file. Doing this first limits the number of delivery *attempts* to once every 24hr.
  // TODO: Consider doing it after we've opened the template file. No harm in retrying for every message
  // if we never reach the call to deliver_to_maildir.
  if ((size_t)snprintf(quotawarnmsg, sizeof(quotawarnmsg), "%s/quotawarn", dir) >= sizeof(quotawarnmsg)) {
    log_event(ERROR, "path too long for quotawarn timestamp file in %s", dir);
    return -2;
  }

  fd = open(quotawarnmsg, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    log_event(ERROR, "couldn't update quotawarn timestamp\n"); // caller usually ignores the return value, so better not to printf
    return -2;
  }
  /* O_TRUNC already updates mtime on an existing file, but say so explicitly: the
   * old zero-byte write() wasn't guaranteed to. */
  if (futimens(fd, NULL) != 0) {
    log_event(ERROR, "couldn't update quotawarn timestamp %s: %s", quotawarnmsg, strerror(errno));
  }
  close(fd);

  if ((read_fd = open(template_path, O_RDONLY)) < 0) {
    log_event(ERROR, "couldn't open quota warning template %s: %s", template_path, strerror(errno));
    return -2;
  }

  /* Don't include Return-Path in quota warnings (since they're computer
   * generated) but add a Date header.
   *
   * The warning has no envelope of its own, so it inherits the recipient of the
   * delivery that triggered it. 5.6 used raw DTLINE here for the bounce mailbox
   * and a path-derived address otherwise, so the same event produced two
   * different spellings of the same thing.
   */
  add_header(extra_headers, sizeof extra_headers, "Delivered-To",
             DealiasedRecipient);

  /* date_header() returns a full "Date: ...\n" line; skip the field name. */
  date = date_header();
  if (strncasecmp(date, "Date:", 5) == 0) {
    date += 5;
    while (*date == ' ' || *date == '\t') {
      ++date;
    }
  }
  add_header(extra_headers, sizeof extra_headers, "Date", date);

  // dir is already the quota root: every caller passes one (see calc_quota_root).
  size_t warning_size = 0;
  err = deliver_to_maildir(dir, dir, extra_headers, read_fd, quota_string, "", 0, &warning_size);
  d->maildir_file_size_bytes = (ssize_t)warning_size;

  close(read_fd);

  d->success = err == 0;
  log_delivery(&gelf, d);
  d->in_progress = false;

  return err;
}


/* 1 if inner is outer or a subdirectory of outer. realpath() so ./Maildir/.Drafts
 * and symlink spellings compare equal; require a '/' or NUL after the prefix so
 * .../admin/Maildir does not match .../admin/Maildir-old. Both paths must exist. */
static int path_is_within(const char *inner, const char *outer) {
  char inner_r[PATH_MAX];
  char outer_r[PATH_MAX];
  size_t n;

  if (inner == NULL || outer == NULL || *inner == '\0' || *outer == '\0') {
    return 0;
  }
  if (realpath(inner, inner_r) == NULL || realpath(outer, outer_r) == NULL) {
    return 0;
  }
  n = strlen(outer_r);
  if (strncmp(inner_r, outer_r, n) != 0) {
    return 0;
  }
  return inner_r[n] == '\0' || inner_r[n] == '/';
}


/* Cheap "is this a maildir?" probe. cur/ only: new/ and tmp/ are ordinary directory
 * names that turn up all over a filesystem, cur/ essentially is not. Same test the
 * maildirfolder walk guard in maildirquota.c uses. */
static bool is_maildir_path(const char *path) {
  struct stat st;
  char probe[PATH_MAX];

  if (path == NULL || *path == '\0') return false;
  if (snprintf(probe, sizeof probe, "%s/cur", path) >= (int)sizeof probe) return false;
  return stat(probe, &st) == 0 && S_ISDIR(st.st_mode);
}


/* Does this directory carry a Maildir++ maildirfolder marker? In a quota root that is a
 * contradiction: the marker means "I am a folder, charge my parent", and docheckquota() and
 * doaddquota() will act on it wherever the parent looks like a maildir -- resolving the
 * accounting somewhere other than where the caller decided it belongs.
 *
 * Deliberately the same test those two make (maildirquota.c), a bare stat() with no check on
 * the file type, so that this predicts what they will do rather than what the specification
 * says they should. Reports nothing; the caller decides whether it is worth a line. */
static bool marked_as_folder(const char *path) {
  struct stat st;
  char probe[PATH_MAX];

  if (path == NULL || *path == '\0') return false;
  if (snprintf(probe, sizeof probe, "%s/maildirfolder", path) >= (int)sizeof probe) return false;
  return stat(probe, &st) == 0;
}


/* Where does the maildirsize governing a delivery into abs_maildir live?
 *
 * Maildir++ folders are flat -- Maildir/.Sent and Maildir/.Sent.2024 are siblings directly
 * under the root -- so a folder's root is exactly one level up, never more, and there is no
 * walk to run away with. A folder is recognised by its leading dot rather than by the
 * maildirfolder marker: vpopmail writes that marker nowhere, and Exim
 * (maildir_quota_directory_regex) and Dovecot (LAYOUT=maildir++) both key on the dot too.
 *
 * The dot is not a convention we are merely copying. It is what maildirquota.c's
 * countsubdir() will actually count -- cur, new, and dot-prefixed children one level deep,
 * .Trash excepted. A quota root may only be charged for contents a rebuild would reproduce,
 * so a non-dot child (a standalone maildir that happens to sit inside another) has to be
 * its own root; charge it upwards and the delta evaporates at the next rebuild.
 *
 * .Trash is the exception in the other direction: countsubdir() skips it, so its contents
 * never count. It still resolves to the account's root here, because that is what the quota
 * is measured against; deliver_to_maildir() is what declines to record consumption for it.
 *
 * This function decides and does not log. Callers that care what it decided can see it in
 * the answer: out differs from abs_maildir exactly when it climbed, and is_trash_folder()
 * separates .Trash from any other folder.
 *
 * Requiring the parent to hold a cur/ is what keeps a maildir whose own name happens to begin
 * with a dot from being treated as a folder of whatever directory it sits in. A leading dot
 * marks a Maildir++ folder only when the thing above it is itself a maildir; on its own it
 * proves nothing.
 *
 * abs_maildir must already be absolute and resolved (realpath). out must point to a buffer
 * of at least PATH_MAX bytes.
 */
static void calc_quota_root(const char *abs_maildir, char *out) {
  const char *base;
  char parent[PATH_MAX];
  size_t n;

  snprintf(out, PATH_MAX, "%s", abs_maildir);

  base = strrchr(abs_maildir, '/'); // a pointer to the final slash in the path
  base = (base == NULL) ? abs_maildir : base + 1;
  n = (size_t)(base - abs_maildir); /* length of the parent path plus its trailing '/' */

  if (n <= 1 || n >= sizeof parent) return; /* at the filesystem root */
  memcpy(parent, abs_maildir, n - 1);       /* everything before the last '/' */
  parent[n - 1] = '\0';

  if (base[0] != '.' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
    /* Not a Maildir++ folder: either a root in its own right, or a standalone maildir that
     * happens to live inside one. Either way it owns its own maildirsize. */
    return;
  }

  if (!is_maildir_path(parent)) return; /* dot-named, but the parent is not a maildir */

  snprintf(out, PATH_MAX, "%s", parent);
}


/* CASE 1 sets the quota root from the database rather than from the destination path. Ask
 * the structural rule where it would have put it, and say so when the two disagree: a
 * disagreement means we are about to record bytes against a maildirsize whose next rebuild
 * will not reproduce them. Logging only -- nothing here changes where the bytes go.
 */
static void audit_own_maildir_quota_root(const char *abs_maildir, const char *quota_root) {
  char structural[PATH_MAX];
  char resolved[PATH_MAX];
  const char *canonical = quota_root;

  /* quota_root is built from pw_dir and is absolute but not canonical, while abs_maildir has
  * been through realpath(). Resolve a local copy before comparing, the way path_is_within()
  * does: a trailing slash or a doubled separator in the db field -- let alone a symlinked
  * prefix -- would otherwise make an ordinary delivery look like a disagreement and log one
  * line per message. Comparison only; the caller's spelling is left alone. */
  calc_quota_root(abs_maildir, structural);
  if (realpath(quota_root, resolved) != NULL) canonical = resolved;

  /* The two agree, so the quota root is not in question. Nothing to report -- including for
   * a .Trash destination, which deliver_to_maildir() reports when it declines to record the
   * consumption, next to the decision itself. */
  if (strcmp(structural, canonical) == 0) return;

  if (strcmp(structural, abs_maildir) == 0) {
    /* The structural rule says this destination owns its own maildirsize, yet the caller is
     * charging somewhere else -- for CASE 1, the account's inbox taken from the db. That
     * happens when the destination is a maildir nested inside the inbox without a leading
     * dot, so it is not a Maildir++ folder:
     *   .../bob/Maildir/archive/   a maildir a migration restored inside bob's Maildir
     *   .../bob/Maildir/Sent/      a folder from a non-Maildir++ layout (Dovecot's
     *                              LAYOUT=fs names folders without the leading dot)
     * Either way a rebuild of the inbox's maildirsize counts only cur, new and dot-prefixed
     * children, so it will not reproduce what we record here. */
    log_event(WARN,
              "%s is a Maildir nested within another Maildir. Consumption will be recorded"
              " into %s/maildirsize, but when that file is rebuilt later it will discard"
              " the data because its algorithm skips non-dot directories.", abs_maildir, quota_root);
    return;
  }

  /* Both named a root, but not the same one. Reachable when the destination is a Maildir++
   * folder of a nested maildir -- .../bob/Maildir/archive/.Sent/ resolves to
   * .../bob/Maildir/archive, while the db says the inbox .../bob/Maildir. Not expected in a
   * tidy tree; logged so it is visible rather than silent. */
  log_event(WARN, "quota root for %s is %s from the db but %s by path shape",
            abs_maildir, quota_root, structural);
}



// homedir - pw_dir from a user record, without /Maildir. Must have passed validate_homedir_path().
bool calc_is_within_homedir(const char *abs_maildir, const char *homedir) {
  char maildir[256];
  snprintf(maildir, sizeof(maildir), "%s/Maildir", homedir); // pw_dir is the homedir without /Maildir/
  /* INBOX or a Maildir++ folder under it (e.g. Maildir/.Drafts). */
  return path_is_within(abs_maildir, maildir);
}


// Look up a domain's directory in the assign file (users/cdb).
// domain - not empty.
// dir_out - AUTH_SIZE. Empty if the domain isn't in the assign file.
// dealiased_domain_out - AUTH_SIZE. The real domain if domain is an alias, otherwise domain. Empty if not found.
void lookup_domain_dir(const char *domain, char *dir_out, char *dealiased_domain_out) {
  char domain_copy[AUTH_SIZE];

  // vadddomain and vaddaliasdomain refuse anything longer, so it can't be in users/cdb.
  // Checked here so vget_assign() never sees a domain it would truncate.
  if (strlen(domain) > MAX_PW_DOMAIN) {
    log_event(DEBUG, "not looking up domain %s in users/cdb: longer than MAX_PW_DOMAIN (%d)", domain, MAX_PW_DOMAIN);
    dir_out[0] = '\0';
    dealiased_domain_out[0] = '\0';
    return;
  }

  // vget_assign modified the content of its first argument, so make a copy first.
  snprintf(domain_copy, sizeof domain_copy, "%s", domain);
  // Note: vget_assign skips the file lookup if it receives the same input as the last time it was called.
  if (vget_assign(domain_copy, dir_out, AUTH_SIZE, NULL, NULL) == NULL) {
    // Normal for maildir paths outside of the main domains tree.
    // Other possibilities include the maildir path referring to a domain that was deleted or renamed.
    dir_out[0] = '\0';
    dealiased_domain_out[0] = '\0';
  }
  else {
    snprintf(dealiased_domain_out, AUTH_SIZE, "%s", domain_copy); // vget_assign wrote the real domain here
  }
}


void audit_unspecified_owner_quota_root(const char *abs_maildir, const char *quota_root) {
  if (strcmp(quota_root, abs_maildir) != 0) {
    /* It climbed, so the destination is a Maildir++ folder and the maildir above it owns the
    * maildirsize. e.g. a valias row naming
    *   /var/vpopmail/domains/example.com/shared/Maildir/.Archive/
    * delivers the message there, but both the allocation and the consumption belong to
    *   /var/vpopmail/domains/example.com/shared/Maildir
    * A .Trash destination lands here too; deliver_to_maildir() is what reports that its
    * consumption is not recorded, next to the decision not to record it. */
    log_event(DEBUG,"Delivering to a Maildir++ sub-folder. quota root for %s is its parent %s", abs_maildir, quota_root);
  }
  if (marked_as_folder(quota_root)) { // has maildirfolder file
    log_event(WARN,"abnormal: quota root for %s is a Maildir++ folder", abs_maildir);
  }
}


/* The Maildir++ folder abs_maildir is, relative to quota_root, as it is named on disk (e.g. ".Archive").
 * Empty when abs_maildir is quota_root itself, or isn't directly beneath it. */
void calc_maildir_subfolder(const char *abs_maildir, const char *quota_root, char *out, size_t len) {
  char canonical_root[PATH_MAX];
  size_t n;

  out[0] = '\0';
  if (realpath(quota_root, canonical_root) == NULL) return;
  n = strlen(canonical_root);
  if (strncmp(abs_maildir, canonical_root, n) == 0 && abs_maildir[n] == '/' && abs_maildir[n + 1] != '\0') {
    snprintf(out, len, "%s", abs_maildir + n + 1);
  }
}


/* "Delivering to <owner>", plus the folder for anything but the inbox. The on-disk folder name
 * is shown the way a mail client would: no leading dot, and "/" for each level, so
 * ".Lists.Work" becomes "Lists/Work". */
void set_delivery_summary(maildir_constraints_t *c) {
  char folder[PATH_MAX];
  const char *src = c->subfolder;
  size_t i = 0;

  if (c->subfolder[0] == '\0') {
    snprintf(c->summary, sizeof c->summary, "Delivering to %s", c->maildir_owner);
    return;
  }
  if (*src == '.') src++;
  for (; *src && i < sizeof folder - 1; src++) {
    folder[i++] = (*src == '.') ? '/' : *src;
  }
  folder[i] = '\0';
  format_log_text(c->summary, sizeof c->summary, "Delivering to %s, folder \"%s\"", c->maildir_owner, folder);
}


/* The facts in c, one "name: value" per line, for a log record's full_message.
 * Lookups that haven't happened yet are left out. */
void format_constraints_detail(const maildir_constraints_t *c, const char *abs_maildir, char *buf, size_t len) {
  int n = snprintf(buf, len, "maildir: %s", abs_maildir);
  if (n < 0 || (size_t)n >= len) return;
  if (c->subfolder[0]) {
    n += snprintf(buf + n, len - n, "\nsubfolder: %s", c->subfolder);
    if ((size_t)n >= len) return;
  }
  n += snprintf(buf + n, len - n, "\nis_own_maildir: %d\nin_main_domains_tree: %d",
    c->is_own_maildir, c->in_main_domains_tree);
  if ((size_t)n >= len) return;
  if (c->inferred_user[0]) {
    n += snprintf(buf + n, len - n, "\ninferred_user: %s", c->inferred_user);
    if ((size_t)n >= len) return;
  }
  if (c->users_cdb_checked) {
    n += snprintf(buf + n, len - n, "\ndomain_found_in_users_cdb: %d", c->domain_found_in_users_cdb);
    if ((size_t)n >= len) return;
  }
  if (c->domain_dir[0]) {
    n += snprintf(buf + n, len - n, "\ndomain_dir: %s", c->domain_dir);
    if ((size_t)n >= len) return;
  }
  if (c->within_domain_dir_checked) {
    n += snprintf(buf + n, len - n, "\nwithin_domain_dir: %d", c->within_domain_dir);
    if ((size_t)n >= len) return;
  }
  if (c->db_checked) {
    n += snprintf(buf + n, len - n, "\nfound_in_db: %d", c->found_in_db);
    if ((size_t)n >= len) return;
  }
  if (c->homedir[0]) {
    n += snprintf(buf + n, len - n, "\nhomedir: %s", c->homedir);
    if ((size_t)n >= len) return;
  }
  if (c->within_owner_maildir_checked) {
    snprintf(buf + n, len - n, "\nwithin_owner_maildir: %d", c->within_owner_maildir);
  }
}


// Check a homedir from a user record before calc_is_within_homedir() compares paths against it.
//   c, abs_maildir - for the detail log only
//   homedir - pw_dir from the user record of owner
//   owner - name@domain of that user record, for log messages only
// Returns true if homedir is usable.
bool validate_homedir_path(const maildir_constraints_t *c, const char *abs_maildir, const char *homedir,
 const char *owner) {
  char detail[FULL_MESSAGE_MAX];

  if (homedir[0] == '\0') {
    // For the recipient, only reachable via a valias line that names a path: other routes either repair
    // the homedir first (ensure_homedir_is_set_in_db), or defer when they chdir into it.
    // We don't defer here, because v5.6 never consulted pw_dir when delivering to a path,
    // so such deliveries must still proceed.
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    log_detailed_event(ERROR, detail, "homedir is empty in db for %s", owner);
    return false;
  }

  // Relative paths in vpopmail.pw_dir are problematic because our current dir varies based
  // on whether we are processing a valias line, an ordinary delivery, a .qmail file, or a defaultdelivery file.
  // If qmail-lspawn tried to pass such a path to qmail-local, it would be rejected as invalid.
  if (homedir[0] != '/') {
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    log_detailed_event(ERROR, detail, "Relative path %s found in db as the homedir of %s. This is not permitted.",
      homedir, owner);
    return false;
  };
  return true;
}


// Take the quota allocation from owner's db record (pw_shell), rather than from maildirsize.
void set_quota_from_db_record(maildir_constraints_t *c, const vqpasswd_copy_t *owner) {
  if (owner->quota_allocation_string[0] == '\0') { // also covers a NULL pw_shell
    log_event(ERROR, "vpopmail user %s@%s has no quota set", owner->name, owner->domain);
    // quota remains empty (better than NOQUOTA) so that we skip any alteration to maildirsize.
    c->quota[0] = '\0';
    c->quota_allocation_source[0] = '\0';
  }
  else {
    snprintf(c->quota, sizeof c->quota, "%s", owner->quota_allocation_string);
    snprintf(c->quota_allocation_source, sizeof c->quota_allocation_source, "db");
  }
}


// CASE 1: Destination maildir is the user's own inbox, or a Maildir++ sub-folder beneath it.
//
// This pathway avoids maildir_to_email, the only exception being the vusage daemon:
//   user_over_maildirquota() => maildir_checkquota() => maildir_to_email()
void calc_own_maildir_constraints(maildir_constraints_t *c, const vqpasswd_copy_t *recipient, const char *abs_maildir,
 bool check_effective_flags) {
  char account[AUTH_SIZE];  // name@domain: the account whose quota, flags and SpamAssassin preferences apply
  snprintf(account, sizeof account, "%s@%s", recipient->name, recipient->domain);

  c->is_own_maildir = true;
  set_quota_from_db_record(c, recipient);

  snprintf(c->quota_root, sizeof c->quota_root, "%s/Maildir", recipient->dir); // where consumption is recorded
  audit_own_maildir_quota_root(abs_maildir, c->quota_root);
  calc_maildir_subfolder(abs_maildir, c->quota_root, c->subfolder, sizeof c->subfolder);
  snprintf(c->maildir_owner, sizeof c->maildir_owner, "%s", account);
  set_delivery_summary(c);
  snprintf(c->spamc_user, sizeof c->spamc_user, "%s", account); // not DealiasedRecipient

  snprintf(c->domain, sizeof c->domain, "%s", TheDomain);
  snprintf(c->overquota_bounce_template_dir, sizeof c->overquota_bounce_template_dir, "%s", TheDomainDir);
  snprintf(c->domain_quota_warning_template_dir, sizeof c->domain_quota_warning_template_dir, "%s", TheDomainDir); // the owner's domain
  snprintf(c->quota_warning_user, sizeof c->quota_warning_user, "%s", c->maildir_owner);

  if (check_effective_flags) {
    calc_effective_flags(recipient->pw_gid, recipient->name, recipient->domain, &c->effective_flags);
  }
}


/* CASE 2: A maildir that isn't the recipient's own, so its owner has to be worked out from the path.
   The path could describe
    - Another user's maildir, from a valias line, e.g. accounts@ delivering into bob's Maildir.
    - A user in a different domain.
    - The maildir specified as a catch-all for a domain, where the local part is not a known user
    - A maildir outside the main domains tree, e.g. /var/vpopmail/test/Maildir/
    - A shared mailbox inside a domain's directory with no row in the db, e.g. .../example.com/shared/Maildir/

 The owner is guessed with maildir_to_email() and verified against users/cdb and the auth backend.
 The delivery path is checked against their homedir before any owner-specific settings are applied.
*/
void calc_other_maildir_constraints(maildir_constraints_t *c, const char *address, const char *abs_maildir,
 bool check_effective_flags) {
  char detail[FULL_MESSAGE_MAX];
    
  calc_quota_root(abs_maildir, c->quota_root);
  audit_unspecified_owner_quota_root(abs_maildir, c->quota_root);
  calc_maildir_subfolder(abs_maildir, c->quota_root, c->subfolder, sizeof c->subfolder);

  // The first argument is quota_root, not address: for a Maildir++ folder the maildirsize lives on the parent.
  if (read_quota_from_maildir(c->quota_root, c->quota, sizeof c->quota) == 0) {
    snprintf(c->quota_allocation_source, sizeof c->quota_allocation_source, "maildirsize");
  }

  /* The quota is measured against the derived domain, but the bounce template is not
  * taken from it. .over-quota.msg is read by the _sender_, who addressed TheDomain and
  * has no relationship with whichever domain this maildir happens to live under:
  * TheDomainDir carries a support contact they can actually use, and it does not
  * disclose the internal routing. */
  snprintf(c->overquota_bounce_template_dir, sizeof c->overquota_bounce_template_dir, "%s", TheDomainDir);
  

  // Don't use abs_maildir for maildir_to_email(): realpath() resolves symlinks in the configured layout,
  // e.g. domains/example.com -> /mnt/vol3/cust42, so the inferred domain would not match users/cdb.
  // Lowercased because both the vauth_getpw() lookup and spamc -u want the case-folded form.
  const char *inferred = maildir_to_email(address);
  if (lowercase_copy(c->inferred_user, sizeof c->inferred_user, inferred) != 0) {
    // maildir_to_email() returns at most 255 bytes, so shouldn't happen.
    log_event(DEBUG, "maildir_to_email result, at %zu bytes, is too long. maildir path was: %s", strlen(inferred), address);
    c->inferred_user[0] = '\0';
    return;
  }
  if (c->inferred_user[0] == '\0') {
    /* maildir_to_email() fails when:
    *  - none of the ancestor directories have a dot in their name
    *  - the path doesn't end in /Maildir
    *  - the path is too shallow: e.g. /bob/Maildir
    *  - the path is relative but doesn't start with ./
    *  - the only dotted ancestor is the first path component: e.g. /example.com/bob/Maildir
    */ 
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    log_detailed_event(DEBUG, detail, "maildir_to_email failed for %s", address);
    return;
  }

  char localpart[AUTH_SIZE] = "";
  char domain[AUTH_SIZE] = "";
  split_email(localpart, domain, c->inferred_user);

  char dealiased_domain[AUTH_SIZE] = "";
  lookup_domain_dir(domain, c->domain_dir, dealiased_domain);
  c->users_cdb_checked = true;
  c->domain_found_in_users_cdb = c->domain_dir[0] != '\0';
  if (c->domain_found_in_users_cdb) {
    c->within_domain_dir_checked = true;
    c->within_domain_dir = path_is_within(abs_maildir, c->domain_dir);
  }
  if (!c->domain_found_in_users_cdb) {
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    if (c->in_main_domains_tree) {
      // Could be a path to a domain that was deleted or renamed. Or someone forgot qmail-newu.
      log_detailed_event(WARN, detail, "Inferred domain %s missing from users/cdb", domain);
    }
    else {
      // Admins might manually create a maildir outside of the normal tree.
      log_detailed_event(DEBUG, detail, "Inferred domain %s missing from users/cdb, outside of main domains tree", domain);
    }
    return;
  }
  if (!c->within_domain_dir) {
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    if (c->in_main_domains_tree) {
      log_detailed_event(WARN, detail, "Unexpected maildir path, inferred domain=%s", dealiased_domain);
    }
    else {
      // Possibly a path outside the tree, where one of the path components coincides with a vpopmail domain name
      log_detailed_event(DEBUG, detail, "Unexpected maildir path, inferred domain=%s, outside of main domains tree", dealiased_domain);
    }
    return;
  }

  snprintf(c->domain_quota_warning_template_dir, sizeof c->domain_quota_warning_template_dir, "%s", c->domain_dir);
  snprintf(c->domain, sizeof c->domain, "%s", dealiased_domain); // used by caller to enforce domain quotas

  vqpasswd_copy_t maildir_owner;  // the user record associated with the destination maildir, if there is one
  bool maildir_owner_found = load_user(&maildir_owner, localpart, dealiased_domain) == 0;
  c->db_checked = true;
  c->found_in_db = maildir_owner_found;
  if (! maildir_owner_found) {
    // A shared mailbox created without vadduser would land here. Rather unlikely.
    // Or an account was deleted, but the deletion process failed such that its directory remains.
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    log_detailed_event(WARN, detail, "Inferred user %s missing from vpopmail db", c->inferred_user);
    return;
  }

  snprintf(c->homedir, sizeof c->homedir, "%s", maildir_owner.dir);
  if (!validate_homedir_path(c, abs_maildir, maildir_owner.dir, c->inferred_user)) {
    return;
  }
  c->within_owner_maildir_checked = true;
  c->within_owner_maildir = calc_is_within_homedir(abs_maildir, maildir_owner.dir);
  if (!c->within_owner_maildir) {
    format_constraints_detail(c, abs_maildir, detail, sizeof detail);
    log_detailed_event(WARN, detail, "Unexpected maildir path, inferred user=%s", c->inferred_user);
    return;
  }

  // High confidence match
  set_quota_from_db_record(c, &maildir_owner);
  snprintf(c->maildir_owner, sizeof c->maildir_owner, "%s", c->inferred_user);
  snprintf(c->quota_warning_user, sizeof c->quota_warning_user, "%s", c->maildir_owner);
  set_delivery_summary(c);
  if (check_effective_flags) {
    calc_effective_flags(maildir_owner.pw_gid, maildir_owner.name, maildir_owner.domain, &c->effective_flags);
    snprintf(c->spamc_user, sizeof c->spamc_user, "%s", c->maildir_owner);
  }
}


// True if abs_maildir is within the Maildir of recipient, i.e. the Maildir itself or a Maildir++ folder under it.
// recipient - must not be NULL
bool calc_is_within_own_maildir(const maildir_constraints_t *c, const vqpasswd_copy_t *recipient,
 const char *abs_maildir) {
  char account[AUTH_SIZE];
  snprintf(account, sizeof account, "%s@%s", recipient->name, recipient->domain);
  if (!validate_homedir_path(c, abs_maildir, recipient->dir, account)) {
    return false;
  }

  return calc_is_within_homedir(abs_maildir, recipient->dir);
  // True for at least:
  // - user exists, no valias lines, no defaultdelivery file, no .qmail file
  // - user exists, no valias lines, defaultdelivery contains ./Maildir/
  // - user exists, executing a valias line containing ":default", defaultdelivery contains ./Maildir/
  // - user exists, executing a valias line containing an absolute path to user's own Maildir
  // - same, but a Maildir++ folder under that Maildir (e.g. ./Maildir/.Drafts/)
  //
  // False only for valias lines that specify a path, e.g. when
  // - the path is not beneath the homedir of this user
  // - recipient->dir/Maildir does not exist on disk, so realpath() fails.
}


/*
Determine how quota-enforcement and anti-spam will be applied to this delivery.

Inputs:
  recipient - the user record found for the envelope recipient address.
    Pass NULL when the db lookup found no matching rows.
  address - path to destination maildir, as written in the delivery instruction.
     If there are symlinks, we mustn't feed abs_maildir to maildir_to_email().
  abs_maildir - absolute path to the maildir. 

Outputs, as fields of *c:
  summary - e.g. Delivering to bob@example.com
  quota - e.g. 1048576S,1000C or NOQUOTA; "" = don't enforce
  spamc_user - e.g. bob@ex.com. Blank means spam check must be skipped
  domain - the domain measured for quota usage, blank means skip domain quota
  overquota_bounce_template_dir - may contain .over-quota.msg, as seen by sender
  domain_quota_warning_template_dir - may contain .quotawarn.msg, as seen by recipient
  quota_warning_user - the owner of the destination maildir, e.g. bob@example.com
  quota_root - where to find the maildirsize file. The file contains allocation and consumption figures.
  quota_allocation_source - "db" or "maildirsize"
  effective_flags - NO_SPAMASSASSIN etc., spamc/maildrop builds only
*/
void calc_maildir_constraints(maildir_constraints_t *c, const vqpasswd_copy_t *recipient, const char *address,
 const char *abs_maildir) {
  memset(c, 0, sizeof *c);
  snprintf(c->summary, sizeof c->summary, "Delivering into %s", abs_maildir); // refined below for some cases
  c->in_main_domains_tree = path_is_within(abs_maildir, DOMAINS_TREE);

  bool check_effective_flags = false;
#if defined(SPAMASSASSIN) || defined(MAILDROP)
  check_effective_flags = true;
#endif
  // Set fallback user flags, which leaves Maildrop enabled by default.
  // We default to no spam check, as losing a message to broken/unwanted filtering 
  // is worse than receiving extra spam.
  c->effective_flags = NO_SPAMASSASSIN;

  if (recipient == NULL || !calc_is_within_own_maildir(c, recipient, abs_maildir)) {
    calc_other_maildir_constraints(c, address, abs_maildir, check_effective_flags);
    return;
  }

  calc_own_maildir_constraints(c, recipient, abs_maildir, check_effective_flags);
}


// INPUT: quota - vpopmail style quota string, e.g. "1000000S,1000C". 
//                quota_mtos can't handle things like "10M".  Caller must pass it through format_maildirquota() first
//                and must not pass through an empty string.
//    quota_source - where the quota _allocation_ data came from, e.g. "db"
// OUTPUT: over_quota_out - really means not enough space to deliver _this_ message.
void calc_over_quota(bool *over_quota_out, bool *nearly_full_after_delivery_out,
 delivery_log_t *d, const char *quota_root, const char *quota, const char *quota_source,
  ssize_t incoming_message_size, storage_t *allocated_bytes_out, storage_t *allocated_count_out) {

  // 1. Convert quota string to bytes. Also obtain limit on number of messages.

  storage_t allocated_bytes = 0;
  storage_t allocated_count = 0;
  int over_quota = 0; // int, to match user_over_maildirquota fn signature

  quota_mtos(quota, &allocated_bytes, &allocated_count);
  d->maildir_quota_allocated_bytes = (int64_t)allocated_bytes;
  snprintf(d->maildir_quota_source, sizeof d->maildir_quota_source, "%s", quota_source);

  // 2. See if delivering the incoming message would exceed the maildir's quota.
  // Consider using maildir_get_consumption() instead, but we'd need to enforce message counts too.

  storage_t initial_bytes = 0;
  storage_t initial_count = 0;
  int source = QUOTA_CALC_UNKNOWN;
  struct timespec quota_check_t0, quota_check_t1;

  // The second call is almost always a cheap cached read, not another full scan.
  int max_attempts=2;
  int ret=0;
  bool race_occurred = false;
  int raced_source; // only read when race_occurred
  d->maildir_quota_check_duration = 0; // summed over all attempts
  for (int attempt=1; attempt<=max_attempts; attempt++) {
    // This may delete and regenerate maildirsize. Also enforces message count based quotas.
    clock_gettime(CLOCK_MONOTONIC, &quota_check_t0);
    ret = user_over_maildirquota(quota_root, quota, (storage_t)incoming_message_size, &over_quota,
                                        &initial_bytes, &initial_count, &source);
    clock_gettime(CLOCK_MONOTONIC, &quota_check_t1);
    double attempt_duration =
        (quota_check_t1.tv_sec - quota_check_t0.tv_sec) +
        (quota_check_t1.tv_nsec - quota_check_t0.tv_nsec) / 1e9;
    d->maildir_quota_check_duration += attempt_duration;

    if (ret != 0) {
      char detail[256];
      char full_message[FULL_MESSAGE_MAX];
      snprintf(detail, sizeof detail,
        "attempt: %d/%d\n"
        "duration: %.3f seconds\n"
        "allocated_bytes: %" PRIu64 "\n"
        "allocated_count: %" PRIu64,
        attempt, max_attempts, attempt_duration, allocated_bytes, allocated_count
      );
      if (ret == -3) {
        snprintf(full_message, sizeof full_message,
          "The modification time on some Maildir directories changed during the course of the quota usage calculation.\n"
          "The maildirsize file was written to disk anyway.\n\n"
          "%s\n"
          "initial_bytes: %" PRIu64 "\n"
          "initial_count: %" PRIu64 "\n"
          "initial_source: %s",
          detail,
          initial_bytes, initial_count,
          quota_calc_source_name(source)
        );
        if (attempt >= max_attempts) {
          //snprintf(gelf.context.exit_full_message, sizeof gelf.context.exit_full_message, "%s", full_message);
          //vexiterr(EXIT_DEFER, ERROR, "", "Unable to complete quota calculation.");
          log_detailed_event(ERROR, full_message, "Maildir changed while maildirsize was being recalculated. Not enforcing quota.");
          *over_quota_out = false;
          *nearly_full_after_delivery_out = false;
          *allocated_bytes_out = allocated_bytes;
          *allocated_count_out = allocated_count;
          return;
        }
        log_detailed_event(WARN, full_message, "Maildir changed while maildirsize was being recalculated. Retrying.");
        race_occurred = true;
        raced_source = source;
        continue;
      }
      else {
        snprintf(full_message, sizeof full_message,
          "Could not rebuild maildirsize. Possible causes: tmp/ missing or not writable, disk full,"
          " filesystem quota, out of memory, storage/NFS error.\n\n%s",
          detail
        );
        snprintf(gelf.context.exit_full_message, sizeof gelf.context.exit_full_message, "%s", full_message);
        vexiterr(EXIT_DEFER, ERROR, "", "Unable to complete quota calculation.");
        //log_detailed_event(WARN, full_message, "Unable to complete quota calculation. Skipping enforcement.");
        // *over_quota_out = false;
        // *nearly_full_after_delivery_out = false;
        // *allocated_bytes_out = allocated_bytes;
        // *allocated_count_out = allocated_count;
        //break;
      };
    }
    else {
      break;
    }
  }
  /* After a race, a cached read is of the maildirsize the raced rebuild just wrote, so report
   * that rebuild as the source. The duration above already includes it. 
   */
  if (race_occurred && source == QUOTA_CALC_MAILDIRSIZE_CACHED) {
    // Here raced_source refers to the source immediately before the successful attempt.
    source = raced_source;
  }

  d->maildir_initial_bytes = (ssize_t)initial_bytes;
  d->maildir_quota_initial_bytes_source = source;
  d->maildir_not_enough_space = over_quota;

  double space_usage_after_delivery = initial_bytes + incoming_message_size;
  double space_usage_percent;
  bool nearly_full_after_delivery;
  if (allocated_bytes == 0) { // must have been a message-count quota, with no byte limit
    space_usage_percent = 100; // not used
    nearly_full_after_delivery = false;
  }
  else {
    space_usage_percent = (space_usage_after_delivery / allocated_bytes) * 100;
    nearly_full_after_delivery = QUOTA_WARN_PERCENT >= 0 && space_usage_percent >= QUOTA_WARN_PERCENT;
  }

  *over_quota_out = over_quota;
  *nearly_full_after_delivery_out = nearly_full_after_delivery;
  *allocated_bytes_out = allocated_bytes;
  *allocated_count_out = allocated_count;
}


// overquota_bounce_template_dir - directory holding the .over-quota.msg template offered to the sender.
// The caller chooses it, because the right answer is not derivable here: for a valias
// pointing at a maildir in another domain, the full mailbox and the domain the sender
// addressed are different domains, and the bounce is read by the sender. See the
// comment at the .over-quota.msg lookup below.
// domain_quota_warning_template_dir - passed to detect_quotawarn_template().
void enforce_maildir_quota(delivery_log_t *d, const char *quota_root, const char *overquota_bounce_template_dir,
 const char *domain_quota_warning_template_dir,
 const char *quota, const char *quota_source, bool* nearly_full_after_delivery_out, const char *quota_warning_user) {
  
  *nearly_full_after_delivery_out=false;

  storage_t allocated_bytes = 0;
  storage_t allocated_count = 0;
  bool over_quota;
  FILE *fs;
  char tmp_file[256];
  char first_line[256] = "";
  int line_num = 0;
  int r;
  char message[256] = "";

  if (strncmp(quota, "NOQUOTA", 2) == 0) {
    d->maildir_quota_allocated_bytes = -1;
    snprintf(d->maildir_quota_source, sizeof d->maildir_quota_source, "%s", quota_source);
    return;
  };

  const char *formatted_buf = format_maildirquota(quota); // returns a static buffer
  char formatted_quota[MAILDIR_QUOTA_SIZE];
  if (strlen(formatted_buf)==0) { 
    // i.e. empty string, e.g. due to:
    // - nothing specified
    // - an explicit zero: 0S, 0C, 0S,0C [worked in v5.4, invalid in v5.6]
    // - garbage: abc, S
    // - fractions below 1 unit: 0.5M
    if (!quota_warning_user || quota_warning_user[0] == '\0') {
      log_event(ERROR,"Invalid quota allocation set for %s: '%s'. Falling back to unlimited quota.",quota_root,quota);
    }
    else { // calc_maildir_constraints documents a rare situation where quota_warning_user is erroneous, so we log quota_root too.
      log_event(ERROR,"Invalid quota allocation set for user %s: '%s', destination was %s. Falling back to unlimited quota.",
        quota_warning_user,quota,quota_root);
    }
    return;
  }
  snprintf(formatted_quota, sizeof formatted_quota, "%s", formatted_buf);

  calc_over_quota(&over_quota, nearly_full_after_delivery_out, d, quota_root, formatted_quota, quota_source, message_size,
    &allocated_bytes, &allocated_count);

  if (over_quota) {
    // 1. Deliver a warning to the _recipient_.
    char quotawarn_template[PATH_MAX];
    if (detect_quotawarn_template(domain_quota_warning_template_dir, quotawarn_template)
        && !quota_warning_sent_recently(quota_root)) {
      // ignore errors, it logs but won't exit or printf:
      if (deliver_quota_warning(quota_root,quotawarn_template,"not enough space",quota,quota_warning_user) == 0) {
        d->maildir_quota_warning_delivered = true;
      };
    }

    // 2. Bounce back to the _sender_ via stdout.
    if (!quota_warning_user || quota_warning_user[0] == '\0') {
      snprintf(message, sizeof message, "Bouncing, not enough space in %s",quota_root);
    }
    else { // calc_maildir_constraints documents a rare situation where quota_warning_user is erroneous, so consider mentioning quota_root too.
      snprintf(message, sizeof message, "Bouncing, not enough space in %s to deliver to %s",quota_root,quota_warning_user);
    }

    /* check for over quota message in domain.
      * This is the domain the sender addressed, not the domain owning the maildir that is
      * actually full. Those differ when a valias routes into another domain, and the
      * addressed domain is the right one here: this text is read by the sender, so it
      * wants that domain's support contact and wording, and it avoids disclosing the
      * internal routing. The claim it leaves the sender with -- the mailbox serving the
      * address they wrote to is full -- is true wherever that maildir physically lives. */
    r = snprintf(tmp_file, sizeof(tmp_file), "%s/.over-quota.msg",
              overquota_bounce_template_dir);
    if ((size_t)r >= sizeof(tmp_file)) {
      vexiterr(EXIT_DEFER, ERROR, "temporary string buffer too short", "$M, unable to prepare bounce message"); // v5.6 message
    }
    if ((fs = fopen(tmp_file, "r")) == NULL) {
      /* if no domain over quota then check in vpopmail dir */
      snprintf(tmp_file, sizeof(tmp_file), "%s/.over-quota.msg", DOMAINS_TREE);
      fs = fopen(tmp_file, "r");
    }

    if (fs == NULL) {
      // v.5.6 had "user is over quota", and possibly double newline
      vexiterr(EXIT_BOUNCE,INFO,"user is over quota. (#5.2.2)\n\n", "%s", message); 
    } 
    while (fgets(tmp_file, sizeof(tmp_file), fs) != NULL) {
      if (++line_num == 1) {
        snprintf(first_line, sizeof first_line, "%.50s", tmp_file);
        trim_newline(first_line);
        strncat(first_line, "...", sizeof first_line - strlen(first_line) - 1);
      }
      fputs(tmp_file, stdout);
    }
    fclose(fs);
    printf("\n"); // preserving v5.6 behaviour
    log_exit(&gelf, EXIT_BOUNCE, false, INFO, first_line, message);
    vexit(EXIT_BOUNCE);
  }
}


// domain     - the domain whose quota is checked, from calc_maildir_constraints(). Cannot be empty string.
// overquota_bounce_template_dir - directory holding the .over-quota.msg template offered to the sender.
// quota_warning_user - owner of the destination maildir, for the warning's log message. May be empty, never NULL.
// domain_quota_warning_template_dir - passed to detect_quotawarn_template().
void enforce_maildir_domain_quota(delivery_log_t *d, const char *quota_root, const char *domain,
 const char *overquota_bounce_template_dir, const char *domain_quota_warning_template_dir,
 const char *quota, const char *quota_warning_user) {
  FILE *fs;
  char tmp_file[256];
  char first_line[256] = "";
  int line_num = 0;
  int r;
  int domain_over_ret;

  /* bk: check domain quota */
  /* it calls vget_limits itself to get the domain limits, and then vget_assign */
  // TheDomain, TheDomainDir, TheDomainUid and TheDomainGid are untouched
  // It returns 0=not over,1=over,-1 error
  domain_over_ret = domain_over_maildirquota(domain, (storage_t)message_size);
  if (domain_over_ret == -1) {
    log_event(ERROR, "Cannot determine whether domain %s is over-quota. Continuing.", domain);
    return;
  }
  if (domain_over_ret == 1) {
    // First deliver a warning to the _recipient_.
    char quotawarn_template[PATH_MAX];
    if (detect_quotawarn_template(domain_quota_warning_template_dir, quotawarn_template)
        && !quota_warning_sent_recently(quota_root)) {
      if (deliver_quota_warning(quota_root, quotawarn_template, "domain over quota", quota, quota_warning_user) == 0) { // ignore errors, it logs but won't exit or printf
        d->maildir_quota_warning_delivered = true;
      };
    }

    // Now bounce back to the _sender_.
    /* check for over quota message in domain */
    r = snprintf(tmp_file, sizeof(tmp_file), "%s/.over-quota.msg", overquota_bounce_template_dir);
    if ((size_t)r >= sizeof(tmp_file)) {
      // v5.6 message
      vexiterr(EXIT_DEFER, ERROR, "temporary string buffer too short", "$M, unable to prepare domain-quota-exceeded bounce message");
    }
    if ((fs = fopen(tmp_file, "r")) == NULL) {
      /* if no domain over quota then check in vpopmail dir */
      snprintf(tmp_file, sizeof(tmp_file), "%s/.over-quota.msg", DOMAINS_TREE);
      fs = fopen(tmp_file, "r");
    }

    if (fs == NULL) {
      // v.5.6 had "domain is over quota", and possibly double newline
      vexiterr(EXIT_BOUNCE, INFO,"domain is over quota. (#5.2.2)\n\n","Bouncing, enforcing domain quota"); 
    }
    while (fgets(tmp_file, sizeof(tmp_file), fs) != NULL) {
      if (++line_num == 1) {
        snprintf(first_line, sizeof first_line, "%.50s", tmp_file);
        trim_newline(first_line);
        strncat(first_line, "...", sizeof first_line - strlen(first_line) - 1);
      }
      fputs(tmp_file, stdout);
    }
    fclose(fs);
    printf("\n"); // preserving v5.6 behaviour.
    log_exit(&gelf, EXIT_BOUNCE, false, INFO, first_line, "Bouncing, enforcing domain quota");
    vexit(EXIT_BOUNCE);
  }
}


// INPUT: address_in - abs or rel path to the maildir, with or without a trailing '/'.
// The caller must chdir to the correct directory first, so that relative paths in address are handled correctly.
// For valias lines we expect this to be the domain dir. For defaultdelivery, its the homedir.
// INPUT: recipient - the user record found for the envelope recipient address.
//   Pass NULL when the db lookup found no matching rows.
void manage_deliver_to_maildir(const char *address_in, const vqpasswd_copy_t *recipient, const char *log_source) {
  char address[PATH_MAX]; // address_in without trailing '/', so paths and logs are spelled one way
  size_t address_len = strlen(address_in);
  while (address_len > 1 && address_in[address_len - 1] == '/') address_len--;
  snprintf(address, sizeof address, "%.*s", (int)address_len, address_in);

  char extra_headers[HEADERS_SIZE] = "";
  char abs_maildir[PATH_MAX];
  maildir_constraints_t c; // filled by calc_maildir_constraints()

  delivery_log_t *d = &gelf.context.delivery;
  bool nearly_full_after_delivery = false;
  bool enforce_quota = true;

  memset(d, 0, sizeof *d);
  d->in_progress = true;
  format_log_text(d->instruction, sizeof d->instruction, "%s/", address);
  d->source = log_source;
  d->method = "maildir";

  format_log_text(d->message, sizeof d->message, "Delivering into %s", address); // set for early exits, refined later
  // Overridden in calc_maildir_constraints for the is_own_homedir case. Kept for inferred_user case.

  //validate_path_to_maildir(char *line)

  // e.g. /var/vpopmail/domains/test.example.com/ruth/Maildir/
  // Note that the current directory affects how "." in maildir is interpreted, but this is OK.
  // e.g. From a valias line, cwd is DomainDir, but from the defaultdelivery file, cwd is the user's dir.

  if (realpath(address, abs_maildir) == NULL) {
    vexiterr(EXIT_BOUNCE, ERROR,"","Target maildir %s not found on disk, realpath failed: %s\n",address, strerror(errno));
  }
  format_log_text(d->maildir_path, sizeof d->maildir_path, "%s", abs_maildir);

  format_log_text(d->message, sizeof d->message, "Delivering into %s", abs_maildir);
  // For the exits below. Replaced by calc_maildir_constraints()'s summary.
  


  struct stat maildir_stat;
  if (stat(abs_maildir, &maildir_stat) != 0) {
    vexiterr(EXIT_BOUNCE, ERROR,"","Target maildir %s not found on disk, stat failed: %s", abs_maildir, strerror(errno));
  };
  if (!S_ISDIR(maildir_stat.st_mode)) {
    vexiterr(EXIT_BOUNCE, ERROR,"","Target maildir %s is not a directory", address);
  }
  /* A directory is not enough: it has to be a maildir. Without this a misdirected
   * instruction such as ./Maildir/cur/ is accepted, and the quota machinery then treats it
   * as a maildir root and leaves a stray maildirsize inside it before the delivery itself
   * fails for want of tmp/ and new/. */
  // Consider also checking for tmp and new early too, but only defer for those ones.
  if (!is_maildir_path(abs_maildir)) {
    vexiterr(EXIT_BOUNCE, ERROR,"","Target maildir %s is not a maildir: it has no cur/ directory", abs_maildir);
  }

  calc_maildir_constraints(&c, recipient, address, abs_maildir);
  
  char constraint_detail[FULL_MESSAGE_MAX];
  format_constraints_detail(&c, abs_maildir, constraint_detail, sizeof constraint_detail);
  log_detailed_event(DEBUG, constraint_detail, "Maildir constraints"); // TODO: verbose mode only

  snprintf(d->message, sizeof d->message, "%s", c.summary);
  snprintf(d->maildir_owner, sizeof d->maildir_owner, "%s", c.maildir_owner);
  if (*c.quota) {
    snprintf(d->maildir_quota_source, sizeof d->maildir_quota_source, "%s", c.quota_allocation_source);
  }

#ifdef MAILDROP
  // If we are delivering via maildrop, it should enforce quota itself.
  enforce_quota = c.effective_flags & NO_MAILDROP;
#endif

  if (*c.quota && enforce_quota) {
    // If over-quota, this will bounce, and not return.
    enforce_maildir_quota(d, c.quota_root, c.overquota_bounce_template_dir, c.domain_quota_warning_template_dir,
      c.quota, c.quota_allocation_source, &nearly_full_after_delivery, c.quota_warning_user);
  }

#ifdef DOMAIN_QUOTAS
  if (*c.domain) {
    enforce_maildir_domain_quota(d, c.quota_root, c.domain, c.overquota_bounce_template_dir,
      c.domain_quota_warning_template_dir, c.quota, c.quota_warning_user);
  }
#endif

  /* Delivered-To always names DealiasedRecipient, never the destination
   * path. It is the token a later delivery searches for, and the destination is
   * already self-evident to anyone reading this mailbox. 5.6 derived an address
   * from the path here via maildir_to_email(), which resolves the owning account
   * correctly for any path laid out as <domain>/<user>/Maildir/ -- including
   * USERS_BIG_DIR hash directories and Maildir++ subfolders, both of which it
   * handles deliberately. What it cannot do is recognise a directory in that tree
   * that is not an account: ".../example.com/shared/Maildir/" yields
   * "shared@example.com", which has no row in the vpopmail table. Either way the
   * spelling differs from the one the loop check searches for.
   * Nothing derived from a Maildir path reaches the headers, which is also why
   * none of them need escaping: TheUser and TheDomain are already restricted by
   * is_username_valid() and is_domain_valid(), neither of which permits CR or
   * LF, whereas valias rows are not validated at all. */

  add_header(extra_headers, sizeof extra_headers, "Return-Path",
             angle_bracketed(ReturnPath));
  add_header(extra_headers, sizeof extra_headers, "Delivered-To",
             DealiasedRecipient);

  // X-Original-To is useful for auditing how a message arrived at its final destination,
  // in cases where Delivered-To doesn't record the envelope recipient address.
  if (strcmp(OriginalRecipient, DealiasedRecipient) != 0) {
    add_header(extra_headers, sizeof extra_headers, "X-Original-To",
               OriginalRecipient);
  }

  size_t delivered_size = 0;
  switch (deliver_to_maildir(address, c.quota_root, extra_headers, 0,
                             c.quota, c.spamc_user, c.effective_flags, &delivered_size)) {
    case -1:
      // v5.6 had EXIT_BOUNCE, "user is over quota". Consider EXIT_DEFER instead.
      vexiterr(EXIT_BOUNCE, ERROR,"Unable to write message. (#4.3.1)","operating-system disk quota exceeded (EDQUOT) for the vpopmail user");
    case -2:
      vexiterr(EXIT_DEFER, ERROR, "system error", "$M while delivering to maildir"); // kept v5.6 wording
    case -3:
      vexiterr(EXIT_BOUNCE, ERROR, "mail is looping", "$M while delivering to maildir"); // kept v5.6 wording
  }
  d->maildir_file_size_bytes = (ssize_t)delivered_size;

  // Here because if the primary delivery failed, there's no size_bytes increase.
  if (nearly_full_after_delivery) {
    d->maildir_nearly_full = true; // don't set earlier
    // Deliver warning to recipient. Ignore errors, it logs but won't exit or printf.
    char quotawarn_template[PATH_MAX];
    if (detect_quotawarn_template(c.domain_quota_warning_template_dir, quotawarn_template)
        && !quota_warning_sent_recently(c.quota_root)
        && deliver_quota_warning(c.quota_root, quotawarn_template, "mailbox nearly full", c.quota, c.quota_warning_user) == 0) {
      d->maildir_quota_warning_delivered = true;
    }
  }

  d->success = true; // irrespective of quota warning delivery failure
  log_delivery(&gelf, d);
  d->in_progress = false;
}


/*
 * Deliver an email to an address
 * calls vexit on failure
 *
 * recipient - the user record found for the envelope recipient address.
 *   Pass NULL when the db lookup found no matching rows.
 */
 // return value: -1 means the caller should stop processing remaining delivery instructions
int deliver_mail(char *address, const vqpasswd_copy_t *recipient, const char *log_source) {
  /* This is a comment, ignore it */
  if (*address == '#') return 0;

  /* This is an command */
  if (*address == '|') {
    /* run the command */
    return run_command(address,log_source); // 0=success; -1 means skip remaining instructions
  }

  /* Starts with '.' or '/', then it's an mbox or maildir delivery */
  else if ((*address == '.') || (*address == '/')) {
    /* check for mbox delivery and exit accordingly */
    if (address[strlen(address) - 1] != '/') {
      vexiterr(EXIT_DEFER, ERROR,"","can't handle mbox delivery for %s", address);
    }

    manage_deliver_to_maildir(address, recipient, log_source);

    /* must be an email address */
  } 
  else {
    /* .qmail / valias / defaultdelivery may prefix the address with '&'.
     * inject_mail and qmail-inject want the bare address. */
    if (*address == '&') ++address;
    inject_mail(address,log_source);
  }
  return 0;
}


/* Check if the vpopmail user has a .qmail file in their directory
 * and foward to each email address, Maildir or program
 *  that is found there in that file
 *
 * recipient - the user record found for the envelope recipient address.
 *   Pass NULL when the db lookup found no matching rows.
 *
 * Return: 1 if we found and delivered email
 *       : OLD: 0 if not found
 *       : -1 if no user .qmail file
 *
 */
int check_forward_deliver(const vqpasswd_copy_t *recipient) {
  char **instructions = NULL;
  int found = -1; // load_text_file(): 0 found, -1 absent, -2 unreadable (logged), treated as absent like 5.6
  int i;

#ifdef QMAIL_EXT
  char tmpbuf[500];

  /* format the file name */
  if (strlen(TheExt)) {
    strcpy(tmpbuf, ".qmail-");
    strcat(tmpbuf, TheExt);
    if ((found = load_text_file(tmpbuf, &instructions)) != 0) {
      for (i = strlen(TheExt); i >= 0; --i) {
        if (!i || TheExt[i - 1] == '-') {
          strcpy(tmpbuf, ".qmail-");
          strncat(tmpbuf, TheExt, i);
          strcat(tmpbuf, "default");
          if ((found = load_text_file(tmpbuf, &instructions)) == 0) {
            break;
          }
        }
      }
    }
  }
#endif

  if (found != 0) found = load_text_file(".qmail", &instructions);

  /* no usable .qmail file at all */
  if (found != 0) {
    return (-1);
  }

  // Treat a 0-bytes file the same as .qmail, that is, the same as if there is no file.
  if (instructions[0] == NULL) {
    free_array(instructions);
    return (-1);
  }

  // Defer when first line is blank, like qmail-local 4.2.1 error.
  // TODO: Q. Does this add value? Should I check for extra whitespace?
  if (instructions[0][0] == '\0') {
    vexiterr(EXIT_DEFER, ERROR, "", ".qmail first line is blank");
  }

  for (i = 0; instructions[i] != NULL; i++) {
    if (*instructions[i] == '#') {
      continue;
    }

    // It's safe to pass the user record data (recipient) because check_forward_deliver is never called by deliver_mail itself.
    if (deliver_mail(instructions[i],recipient,".qmail") == -1) { // e.g. from child process exit code 99, if we enable that feature
      break;
    }
  }

  free_array(instructions);

  // TODO: warn when there were only comments and blank lines

  return (1);
}


/*
 * Returns true if the supplied path is deemed to be a homedir.
 * This supports a longstanding, but undocumented feature where
 * the second argument to vdelivermail can be a path to a homedir.
 *
 * These tests allow for the possibility that the user could specify a Maildir
 * called something other than "Maildir".
 *
 * Returns false if the path does not refer to an existing directory.
 *
 * Returns true if ANY of the following holds:
 *   - the directory contains a subdirectory called "Maildir"
 *   - the directory contains a file called ".qmail"
 *   - the path does not end in '/'
 * Otherwise false.
 */
static bool detect_homedir(const char *path) {
  struct stat st;
  char subpath[PATH_MAX];
  size_t n;

  /* If path does not refer to a directory that exists, return false */
  if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    return false;
  }

  // Path doesn't end in '/', so we know it's not a Maildir.
  // Check first to simplify stat calls.
  n = strlen(path);
  if (n == 0 || path[n - 1] != '/') {
    return true;
  }

  /* Directory contains a 'Maildir' subdirectory */
  snprintf(subpath, sizeof(subpath), "%sMaildir", path);
  if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
    return true;
  }

  /* Directory contains a '.qmail' file */
  snprintf(subpath, sizeof(subpath), "%s.qmail", path);
  if (stat(subpath, &st) == 0 && S_ISREG(st.st_mode)) {
    return true;
  }

  return false;
}


/*
 * the vpopmail user does not exist. Follow the rest of
 * the directions in the .qmail-default file
 */
// For the catch-all path, we aim to return, rather than vexit.
// If we got here via :default there may be additional valias instructions to process.
void usernotfound() {
  int r;
  int call_dir;
  int dot_qmail_executed=0;
  char msg[AUTH_SIZE + 64]; // fixed text plus DealiasedRecipient

  if (strcmp(bounce, DELETE_ALL) == 0) {
    gelf.context.user_not_found = true;
    // Not using vexiterr because we need to log success=false
    snprintf(msg, sizeof(msg), "Discarding, %s not found",DealiasedRecipient);
    log_exit(&gelf, EXIT_OK, false, INFO, NULL, msg); 
    vexit(EXIT_OK);
  }

  /* If they want to bounce the email back then
    * print a message and exit 100
    */
  if (strcmp(bounce, BOUNCE_ALL) == 0) {
    gelf.context.user_not_found = true;

    FILE *fs;
    char tmp_file[256];
    char first_line[256] = "";
    int line_num = 0;

    r = snprintf(tmp_file, sizeof(tmp_file), "%s/.no-user.msg", TheDomainDir);
    if ((size_t)r >= sizeof(tmp_file)) {
      vexiterr(EXIT_DEFER, ERROR, "temporary string buffer too short", "$M"); // v5.6 message
    }
    if ((fs = fopen(tmp_file, "r")) == NULL) {
      /* if no domain no user then check in vpopmail dir */
      snprintf(tmp_file, sizeof(tmp_file), "%s/.no-user.msg", DOMAINS_TREE);
      fs = fopen(tmp_file, "r");
    }
    if (fs == NULL) {
      vexiterr(EXIT_BOUNCE,INFO,"Sorry, no mailbox here by that name. (#5.1.1)","Bouncing, %s not found", DealiasedRecipient); // sent basic message
    };
    // Sadly qmail-send will log up to 3000 bytes of our custom message to its log stream, replacing newlines with "/".
    while (fgets(tmp_file, sizeof(tmp_file), fs) != NULL) {
      if (++line_num == 1) {
        snprintf(first_line, sizeof first_line, "%.50s", tmp_file);
        trim_newline(first_line);
        strncat(first_line, "...", sizeof first_line - strlen(first_line) - 1);
      }
      fputs(tmp_file, stdout);
    }
    fclose(fs);
    snprintf(msg, sizeof(msg), "Bouncing, %s not found", DealiasedRecipient);
    log_exit(&gelf, EXIT_BOUNCE, false, INFO, first_line, msg); // sent .no-user.msg
    vexit(EXIT_BOUNCE);
  }

  // Not setting user_not_found here. That's only for a user-not-found *error*, after which we exit immediately.
  gelf.context.catchall = true;

  /* check if it is a path */
  // for valias lines, relative paths are relative to is DomainDir
  if (bounce[0] == '/' || bounce[0] == '.') { 
    if (detect_homedir(bounce)) {
      // Undocumented homedir form, used by things like vadddomain -e postmaster,
      // which writes domain_dir/postmaster. Valias lines do not support this form.

      // Remove the trailing "/"
      if (bounce[strlen(bounce) - 1] == '/' && strlen(bounce) > 1) {
        bounce[strlen(bounce) - 1] = '\0';
      }

      log_event(INFO,"Routing to catch-all instruction, %s not found", DealiasedRecipient);
      if (gelf.config.execute_dotqmail) {
        call_dir = open_current_directory();
        Chdir(bounce);
        dot_qmail_executed = check_forward_deliver(NULL) != -1;
        if (dot_qmail_executed) {
          log_event(DEBUG, "finished executing .qmail file within catch-all homedir");
          Fchdir(call_dir);
          close(call_dir);
          return;
        }

        // Current directory must be restored, as a relative path in bounce would descend again during manage_deliver_to_maildir.
        Fchdir(call_dir);
        close(call_dir);
      }
      char maildir[PATH_MAX]; // bounce is at most AUTH_SIZE - 1 bytes, so this fits
      snprintf(maildir, sizeof maildir, "%s/Maildir/", bounce);
      manage_deliver_to_maildir(maildir, NULL, "catchall");
      return;
    } 
    else {
      // Ordinary qmail delivery instruction: must be a path to a Mailbox or Maildir
      if (bounce[strlen(bounce) - 1] != '/') {
        vexiterr(EXIT_DEFER, ERROR,"","user does not exist, Mailboxes (as opposed to Maildirs) are not supported");
      }
      // Not using vexiterr to log at INFO level. 
      log_event(INFO, "Routing to catch-all instruction, %s not found", DealiasedRecipient);
      manage_deliver_to_maildir(bounce, NULL, "catchall");
      return;
    }
  }

  // This must be a catch-all email address, or a shell command. 
  // Current directory TheDomainDir, preserving v5.6 behaviour for shell commands.
  log_event(INFO, "Routing to catch-all instruction, %s not found", DealiasedRecipient);
  deliver_mail(bounce,NULL,"catchall");
  return;
}


// INPUT: recipient - the user record found for the envelope recipient address.
//   Pass NULL when the db lookup found no matching rows.
void action_default_delivery(char** instructions, const vqpasswd_copy_t *recipient) {
  char* line;
  int count=array_count(instructions);

  for (int i=1; i<=count; i++) {
    line = instructions[i-1];
    if(line[0]=='|' && strstr(line, "vdelivermail")!=NULL) {
      DeprecationWarning = 1;
      log_event(WARN,"Shell command containing 'vdelivermail' within defaultdelivery is deprecated. Delivering to ./Maildir/ instead.");
      // Preserve vpopmail 5.6 behaviour:
      manage_deliver_to_maildir("./Maildir/",recipient,"defaultdelivery");
      if (i != count) {
        log_event(ERROR,"defauldelivery contained 'vdelivermail' and fall-back delivery succeeded. Skipping remaining instructions to preserve legacy behaviour.");
      };
      return;
    }

    if (deliver_mail(instructions[i-1],recipient,"defaultdelivery") == -1) {
      break;
    }
  }
}


// INPUT: recipient - the user record found for the envelope recipient address.
//   Pass NULL when the db lookup found no matching rows.
// RETURN VALUE: 0 means caller should fallback to ordinary delivery
int check_default_delivery(const vqpasswd_copy_t *recipient) {
  char** instructions;
  int loaded = load_text_file(DefaultDeliveryFile, &instructions);

  if (loaded == -1) {
    return 0;
  }
  if (loaded == -2) {
    // Falling back to ordinary delivery could put mail where the real delivery agent never looks.
    vexiterr(EXIT_DEFER, ERROR, "", "defaultdelivery file %s can't be used", DefaultDeliveryFile);
  }
  if (instructions[0] == NULL) {
    log_event(WARN,"defaultdelivery file has 0 bytes, falling back to ordinary delivery");
    free_array(instructions);
    return 0;
  };
  //validate_default_delivery(instructions, 0); // fatal on error, won't pickup issues with individual instructions

  if (count_non_comment_instructions(instructions) == 0) {
    log_event(WARN,"defaultdelivery exists, is larger than 0 bytes, but has no delivery instructions. Technically valid, but mail silently discarded!"); 
    return 1;
  }

  char** cleaned;
  clean_instructions(&cleaned, instructions);
  free_array(instructions);
  action_default_delivery(cleaned, recipient);
  free_array(cleaned);

  return 1;
};


/*
 * check for locked account
 * deliver to .qmail file if any
 * else deliver to etc/vdefaultdelivery if that file isn't empty
 *                  (a vdelivermail line there means ./Maildir/)
 *
 * recipient - the user record found for the envelope recipient address. Must not be NULL.
 */
void checkuser(vqpasswd_copy_t *recipient) {
  char maildir[AUTH_SIZE];
  int call_dir;
  char msg[AUTH_SIZE + 64]; // fixed text plus DealiasedRecipient

  snprintf(gelf.context.user, sizeof(gelf.context.user), "%s@%s", recipient->name, recipient->domain);

  if (recipient->pw_gid & BOUNCE_MAIL) {
    snprintf(msg, sizeof(msg), "vdelivermail: account is locked email bounced %s\n", DealiasedRecipient); // v5.6 exact: TheUser@TheDomain
    vexiterr(EXIT_BOUNCE, INFO, msg, "%s@%s user is locked, email bounced", recipient->name, recipient->domain);
  };

  if (gelf.config.ensure_homedir_is_set_in_db) {
    ensure_homedir_is_set_in_db(recipient); // this modifies recipient->dir !
  }
  if (gelf.config.ensure_homedir_exists_on_disk) {
    ensure_homedir_exists_on_disk(recipient);
  }

  call_dir = open_current_directory();
  Chdir(recipient->dir);

  /* check for a .qmail file in their homedir
  * If it exists, then deliver to the contents and exit
  */
  if (gelf.config.execute_dotqmail && check_forward_deliver(recipient) != -1) {
    Fchdir(call_dir);
    close(call_dir);
    return;
  }

  // fatal on error. Returns 0 to tell us to fallback to ordinary delivery.
  if (check_default_delivery(recipient)) {
    Fchdir(call_dir);
    close(call_dir);
    return;
  };

  snprintf(maildir, sizeof(maildir), "%s/Maildir/", recipient->dir);
  manage_deliver_to_maildir(maildir, recipient, "");

  Fchdir(call_dir);
  close(call_dir);
}


void load_aliases(char*** lines, char* user, char* domain) {
  char* tmpstr;
  tmpstr = valias_select(user, domain);
    
  if (tmpstr == NULL && verrori != 0) {
    // v5.6 message from main()
    vexiterr(EXIT_DEFER, ERROR,"vdelivermail: deferred, database down","can't load valias rows, verrori=%d", verrori);
  }

  while (tmpstr != NULL) {
    array_push(lines, tmpstr);
    tmpstr = valias_select_next();
  }
}


#ifdef VALIAS
/* Record every valias line, comments included, in gelf.context.valias_instructions
 * for the exit log: '\n' between lines, none after the last. Each line is
 * sanitised on its own (sanitising the joined text would turn the '\n'
 * separators into U+FFFD). A line that won't fit is left out whole, along
 * with every line after it, and the field ends with "... N more" instead:
 * those are the lines most likely never to have run. */
#define VALIAS_MORE_RESERVE 24          /* room for "\n... <int> more" */
void record_valias_instructions(char **lines) {
  char *buf = gelf.context.valias_instructions;
  size_t size = sizeof(gelf.context.valias_instructions);
  size_t used = 0;
  int count = array_count(lines);
  int i;

  buf[0] = '\0';
  for (i = 0; i < count; i++) {
    char line[HEADER_VALUE_MAX];
    bool cut = snprintf(line, sizeof line, "%s", lines[i]) >= (int)sizeof line;
    size_t sep = (i > 0) ? 1 : 0;
    size_t len;
    size_t limit;

    sanitise_inplace(line, sizeof line, cut, NULL, NULL);
    len = strlen(line);
    /* Keep room for "\n... N more" unless this is the last line. */
    limit = (i == count - 1) ? size - 1 : size - 1 - VALIAS_MORE_RESERVE;
    if (used + sep + len > limit) {
      snprintf(buf + used, size - used, "%s... %d more", sep ? "\n" : "", count - i);
      return;
    }
    if (sep) {
      buf[used++] = '\n';
    }
    memcpy(buf + used, line, len + 1);
    used += len;
  }
}


struct save_env_t {
  char value[AUTH_SIZE];
  bool was_set;
};

// Put DEFAULT back to the value qmail-local set, or remove it if qmail-local didn't set it.
void restore_non_wildcard_environment(const struct save_env_t *save_env) {
  if (save_env->was_set) {
    setenv("DEFAULT", save_env->value, 1);
  }
  else {
    unsetenv("DEFAULT");
  }
}


/*
 * Process any valiases for this user@domain
 *
 * This will look up any valiases in vpopmail and
 * deliver the email to the entries
 *
 * Return 1 if aliases found
 * Return 0 if no aliases found
 */
int process_valias(void) {
  // A wildcard candidate: a prefix of TheUser plus "default" (sizeof includes the NUL).
  char tmpuser[sizeof(TheUser) - 1 + sizeof("default")];
  int i;
  int idx;
  int call_dir;
  char maildir[AUTH_SIZE];
  char** valias_lines = NULL;
  int limit_count=0;
  char* instruction;
  char matched_local_part[sizeof tmpuser] = ""; // TheUser, TheUserExt or tmpuser
  bool matched = false;
  bool wildcard_mode = false;
  char wildcard_remainder[AUTH_SIZE] = "";
  struct save_env_t save_env = {0};

  if (getenv("DEFAULT") != NULL) {
    save_env.was_set=true;
    snprintf(save_env.value, sizeof save_env.value, "%s", getenv("DEFAULT"));
  }

  // look for an exact match, e.g. bob-shopping@. See if there is a "bob-shopping" valias line.
  load_aliases(&valias_lines, TheUser, TheDomain);
  if (array_count(valias_lines) > 0) {
    matched = true;
    snprintf(matched_local_part, sizeof matched_local_part, "%s", TheUser);
  }

  /* check for wildcard (ending with "-default") if there's no exact match */
  // e.g. cut off the everything beyond the last hyphen. e.g. for bob-shopping, it looks for "bob-default"
  if (!matched) {
    for (i = strlen(TheUser); i > 0; --i) {
      if (TheUser[i - 1] == '-') {
        tmpuser[0] = '\0';
        strncat(tmpuser, TheUser, i);
        strcat(tmpuser, "default");
        load_aliases(&valias_lines, tmpuser, TheDomain);
        if (array_count(valias_lines) > 0) {
          matched = true;
          snprintf(matched_local_part, sizeof matched_local_part, "%s", tmpuser);

          // e.g. "myer", for bob-shopping-myer, for a valias row "bob-shopping-default"
          snprintf(wildcard_remainder, sizeof wildcard_remainder, "%s", &TheUser[i]); 
          wildcard_mode=true;
          break;
        }
      }
    }
  }

#ifdef QMAIL_EXT
  if (!matched) {
    /* try the bare base name (prefix before the first '-') when nothing else matched */
    // e.g. look for bob, if the message was addressed to bob-something@
    if (array_count(valias_lines) == 0 && strcmp(TheUser, TheUserExt) != 0) {
      load_aliases(&valias_lines, TheUserExt, TheDomain);
      if (array_count(valias_lines) > 0) {
        matched = true;
        snprintf(matched_local_part, sizeof matched_local_part, "%s", TheUserExt);
      }
    }
  }
#endif

  // must calc before removing comments. A lone comment row must return found=1.
  if (array_count(valias_lines) == 0) {
    gelf.context.valias_count = 0;
    return 0;
  };

  record_valias_instructions(valias_lines);

  // The user record is found the same way as main() does, whichever valias row matched.
  // A row keyed by an existing user acts as that user's .qmail; a wildcard row is domain-level,
  // and gains a user only via QMAIL_EXT.
  // :default then delivers as checkuser() would for that user, without consulting their own valias rows.
  // Note: Technically the db can have a valias row without a corresponding row in vpopmail.
  vqpasswd_copy_t recipient;
  bool found = load_user(&recipient, TheUser, TheDomain) == 0;
#ifdef QMAIL_EXT
  if (!found && strcmp(TheUser, TheUserExt) != 0) { // e.g. look for plain "bob" if the addressed user is bob-something@
    found = load_user(&recipient, TheUserExt, TheDomain) == 0;
  }
#endif
  if (found) {
    snprintf(gelf.context.user, sizeof(gelf.context.user), "%s@%s", recipient.name, recipient.domain);
  }
  // continue, even when not found. This would be a alias-only set of lines.

  char** cleaned;
  clean_instructions(&cleaned, valias_lines);
  free_array(valias_lines);
  limit_count = array_count(cleaned);

  gelf.context.valias_count = limit_count; // Defined as number of non-comment lines.

  // Detect when valias lines are all comments. Check after load_user so we can log the user, when known.
  if (limit_count == 0) {
    if (!found) {
      log_event(INFO,"Discarding mail, valias lines for %s@%s are only comments, user does not exist",matched_local_part, TheDomain);
    }
    else {
      // This is the most straight-forward way to silently disable normal delivery for a user.
      log_event(INFO,"Discarding mail for %s@%s", recipient.name, recipient.domain);
    }
    return 1; // sic
  }

  call_dir = open_current_directory(); // i.e. TheDomainDir

  gelf.context.valias_completed=0; // how many non-comment lines completed without a failure

  bool bounce_or_delete = strcmp(bounce, BOUNCE_ALL) == 0 || strcmp(bounce, DELETE_ALL) == 0;

  for (idx = 1; idx <= limit_count; idx++) {
    instruction = cleaned[idx-1];

    // Handling :default here avoids deliver_mail calling itself recursively.
    if (strcmp(instruction, ":default") == 0) {

      if (!found) {
        // Domains that use catch-all addresses may derive some utility from calling :default
        // on a valias line, even when there's no matching user in the vpopmail table.
        if (bounce_or_delete && idx != limit_count) {
          // Probably unintentional, so let it bounce, even when SENDER is empty (double bounce).
          log_event(ERROR,"%s has :default in valias table, no corresponding user in vpopmail table"
          " and %s for user-not-found. The %s will cause remaining instructions"
          " to be skipped.",DealiasedRecipient, bounce, bounce);
        }
        else {
          log_event(INFO,"%s has :default in valias table, but no corresponding user in vpopmail table."
            " Triggering user-not-found instruction.",DealiasedRecipient);
        }
        
        // This could deliver to a catch-all address, run a command etc. bounce-no-mailbox or other failures will exit.
        usernotfound();
        gelf.context.valias_completed++; 
          // We don't count bounce or delete here as a completion:
          // They interrupt execution, have success=false, and are probably a configuration error.
        continue;
      };

      // The remaining code is like checkuser(), but successful deliveries do not vexit...

      if (recipient.pw_gid & BOUNCE_MAIL) {
        // we have to vexit to trigger the bounce
        char msg[AUTH_SIZE + 64]; // fixed text plus DealiasedRecipient
        snprintf(msg, sizeof(msg), "vdelivermail: account is locked email bounced %s\n", DealiasedRecipient); // v5.6 message
        vexiterr(EXIT_BOUNCE, WARN, msg, "user is locked, cannot complete :default directive");
      };

      if (gelf.config.ensure_homedir_is_set_in_db) {
        ensure_homedir_is_set_in_db(&recipient);
      }
      if (gelf.config.ensure_homedir_exists_on_disk) {
        ensure_homedir_exists_on_disk(&recipient);
      }

      Chdir(recipient.dir);

      // Check for a .qmail file in their Maildir
      // If it exists, then deliver to the contents.
      if (gelf.config.execute_dotqmail && check_forward_deliver(&recipient) != -1) {
        gelf.context.valias_completed++;
        Fchdir(call_dir);
        continue; // There could be other valias lines.
      };
      // There must have been no .qmail file.

      // These features were never implemented by deliver_mail for "/" or "./":
      // make_user_dir - dovecot cannot do. We don't want vpopmail writing to NFS share anyway.
      // vmake_maildir - dovecot can do that for us, not needed if we called vadduser, perhaps safer without
      // check_forward_deliver - a whole new interpreter loop, has quota bug, also does chdir; there are no .qmail files within our domains

      // Current directory is still the user's.
      if (check_default_delivery(&recipient)) { // return of 0 means fallback to ordinary delivery
        gelf.context.valias_completed++;
        Fchdir(call_dir);
        continue;
      };

      // We don't have access to qmail-start's aliasempty arg, so we assume ./Maildir/
      snprintf(maildir, sizeof(maildir), "%s/Maildir/", recipient.dir);
      manage_deliver_to_maildir(maildir, &recipient, "valias");
      gelf.context.valias_completed++;
      Fchdir(call_dir);
    }
    else {
      /* deliver the mail, with no user record if none was found */

      if (wildcard_mode) {
        setenv("DEFAULT", wildcard_remainder, 1);
      }

      if (deliver_mail(instruction, found ? &recipient : NULL, "valias") == -1) { 
        // -1 means we should stop, but report success
        gelf.context.valias_completed++;
        if (wildcard_mode) {
          restore_non_wildcard_environment(&save_env); 
        };
        break;
      }
      gelf.context.valias_completed++;
      if (wildcard_mode) {
        restore_non_wildcard_environment(&save_env); 
      };
    }
  }

  close(call_dir);

  return 1;
}
#endif


/* Has this message already been delivered to this address? */
/* Also see prevent_mail_forwarding_loop() */
void check_for_mail_loop(char *recipient) {
  char **delivered_to = NULL;
  collect_delivered_to(&delivered_to);
  if (is_looping(delivered_to, recipient) == 1) {
    snprintf(gelf.context.exit_full_message, sizeof(gelf.context.exit_full_message),
      "Mail is looping: this message already has a Delivered-To line "
      "for %s. Typical causes: a valias/.qmail that forwards this "
      "address to itself; an off-box forward that came back to us via SMTP; "
      "or a POP/IMAP retriever (fetchmail and similar) delivering "
      "back to an address it collected from.",
      recipient);
    append_delivered_to(gelf.context.exit_full_message, sizeof(gelf.context.exit_full_message), delivered_to);
    free_array(delivered_to);
    gelf.context.is_looping = true;
    vexiterr(EXIT_BOUNCE, ERROR, "mail is looping", "$M"); // v5.6 message
  }
  free_array(delivered_to);
}


/*
 * The email message comes in on file descriptor 0 - stdin
 * The user to deliver the email to is in the EXT environment variable
 * The domain to deliver the email to is in the HOST environment variable
 */
int main(int argc, char **argv) {
  bool within_qmail_default = check_qmail_default() == 0;
  
  // Switches like -v need to work, even when configuration files are invalid.
  if (! within_qmail_default) {
    process_interactive_mode_switches(argc, argv);
  }

  // Avoid creating root-owned log files, message files, maildirsize etc.!
  if (getuid() == 0 || geteuid() == 0) {
    if (within_qmail_default) {
        printf(STANDARD_DEFER_MESSAGE "\n");
        vexit(EXIT_DEFER); // if we are called by maildrop, it receives EPIPE before it can see our exit code.
    }
    printf("Aborting: vdelivermail won't deliver as root; run it as the domain's owner, e.g. " VPOPUSER "\n");
    exit(1);
  }

  // Enable logging early, so we can report on incorrect command-line options.
  char reason[1024];
  if (gelf_setup(&gelf, reason, sizeof(reason)) != 0) {
    if (within_qmail_default) {
        printf("%s. (#4.3.0)\n", reason);
        vexit(EXIT_DEFER); // if we are called by maildrop, it receives EPIPE before it can see our exit code.
    }
    exit(1);
  }

  // Any failure here is held over, so that the start event is logged first and
  // stdin is drained before our exit code becomes visible to a piping caller.
  pending_exit_t pending;
  int failed = get_environment(&pending);

  // Set DealiasedRecipient, TheDomain, TheDomainDir, TheDomainUid, TheDomainGid.
  // It would be safer to call lookup_domain_globals after log_process_start, 
  // but it's so much nicer for a search on "domain" to inclde the start log.
  // vget_assign typically reads a local cdb file, so it's unlikely to hang.
  // Consider calling whenever OriginalDomain is set, even when failed=1.
  failed = failed || lookup_domain_globals(OriginalDomain, &pending);

  log_process_start(&gelf);

  if (failed) {
    vexiterr_report(&pending);
    vexit(pending.exit_code);
  }

  // Parse command-line args. Bad input will log a failure.
  get_arguments(argc, argv);

  extract_headers(&gelf.context.headers, gelf.config.tracking_header);
  gelf.context.headers_extracted = true;

  check_for_mail_loop(DealiasedRecipient);

#ifdef VALIAS
  /* process valiases if configured */
  if (process_valias() == 1) {
    // This was the v5.6 message. Decided never to emit the defaultdelivery DeprecationWarning on this path.
    vexiterr(EXIT_OK, INFO, "vdelivermail: valiases processed", "Exiting, success");
  }
#endif

  vqpasswd_copy_t recipient;

  /* get the user from vpopmail database */
  if (load_user(&recipient, TheUser, TheDomain) == 0) {
    checkuser(&recipient); 
    // then remaining else branches are skipped
  }
#ifdef QMAIL_EXT
  /* try and find user that matches the QmailEXT address if: no user found,
   * and the QmailEXT address is different, meaning there was an extension
   */
  else if (strcmp(TheUser, TheUserExt) != 0) {
    /* get the user from vpopmail database */
    if (load_user(&recipient, TheUserExt, TheDomain) == 0) {
      checkuser(&recipient);
      // then remaining else branches are skipped
    } 
    else {
      usernotfound(); // but we only need to say we couldn't find the untrimmed name, i.e. TheUser@TheDomain i.e., DealiasedRecipient 
    }
  }
#endif

  else
    usernotfound();

  // Send a warning into qmail-send's log. Emitting any earlier could leak it into the body of bounce emails.
  if (DeprecationWarning) {
    vexiterr(EXIT_OK, ERROR, "vdelivermail: defaultdelivery file contained deprecated 'vdelivermail' shell command", "Exiting, success");
  };

  /* exit successfully and have qmail delete the email */
  vexiterr(EXIT_OK, INFO, NULL, "Exiting, success");
}

