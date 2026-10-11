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
  gelf.c - structued logging sub-system for vpopmail.
    GELF is Graylog Extended Log Format

  To test:
    export VPOPMAIL_VDELIVERMAIL_CONFIG=$PWD/vdelivermail.ini
    HOST=example.com EXT=admin SENDER=sender@example.net RPLINE=$'Return-Path: <sender@example.net>\n' ./vdelivermail -d '' delete <test.eml
    ./vdelivermail -t
    ./vdelivermail -v

    To test GELF logging with compression=none:
    socat -u UDP-RECVFROM:12201,fork SYSTEM:'tee | jq .'

    With compression=gzip:
    socat -u UDP-RECVFROM:12201,fork SYSTEM:'gzip -cdf | jq .'
*/

/* config.h first: it defines _GNU_SOURCE, which only takes effect ahead of any system
 * header, and HAVE_CURL_GETDATE, which decides whether curl/curl.h is included at all. */
#include "config.h"
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#ifdef HAVE_CURL_GETDATE
#include <curl/curl.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include <ini.h>
#include "vpopmail.h"
#include "gelf.h"
#include "header_text.h"
#include "maildirquota.h" // for QUOTA_CALC_* constants
#include "vdelivermail.h" // for EXIT_BOUNCE/EXIT_DEFER/EXIT_OK

#define GELF_CONFIG_ENV "VPOPMAIL_VDELIVERMAIL_CONFIG"
/* Graylog's usual single-datagram limit for GELF/UDP (incl. gzip payload). */
#define GELF_UDP_MAX 8192


/*
 * The RFC 5424 severity names, in syslog(3) order. These are the only
 * spellings accepted by the min_severity keys; matching is case-insensitive.
 */
static const struct {
  const char* name;
  int severity;
} severity_names[] = {
  {"emerg",   LOG_EMERG},
  {"alert",   LOG_ALERT},
  {"crit",    LOG_CRIT},
  {"err",     LOG_ERR},
  {"warning", LOG_WARNING},
  {"notice",  LOG_NOTICE},
  {"info",    LOG_INFO},
  {"debug",   LOG_DEBUG},
};

#define SEVERITY_NAME_LIST "emerg alert crit err warning notice info debug"

/* The name for a severity number, or NULL if it is not one of the eight. */
static const char *severity_name(int severity) {
  size_t i;

  for (i = 0; i < sizeof(severity_names) / sizeof(severity_names[0]); i++) {
    if (severity_names[i].severity == severity) {
      return severity_names[i].name;
    }
  }
  return NULL;
}


/* Returns 0 and sets *out on success, -1 if value is not a severity name. */
static int parse_severity(const char* value, int* out) {
  size_t i;

  for (i = 0; i < sizeof(severity_names) / sizeof(severity_names[0]); i++) {
    if (strcasecmp(value, severity_names[i].name) == 0) {
      *out = severity_names[i].severity;
      return 0;
    }
  }
  return -1;
}


/*
 * Fold an RFC 5322 header name into the form used for GELF field names:
 * lowercase, every run of non-alphanumerics becomes a single underscore,
 * and no leading or trailing underscore. "X-Submission-ID" ->
 * "x_submission_id". The result always satisfies GELF's ^[\w.\-]*$.
 * Writes an empty string if nothing alphanumeric survives.
 */
static void snake_case(const char* in, char* out, size_t len) {
  size_t i, o = 0;
  int pending_underscore = 0; /* suppresses a leading one */

  for (i = 0; in[i] != '\0' && o + 1 < len; i++) {
    unsigned char ch = (unsigned char)in[i];

    if (isalnum(ch)) {
      if (pending_underscore && o > 0) {
        out[o++] = '_';
      }
      pending_underscore = 0;
      if (o + 1 < len) {
        out[o++] = (char)tolower(ch);
      }
    } else if (o > 0) {
      pending_underscore = 1;
    }
  }
  out[o] = '\0';
}


/*
 * An RFC 5322 field name is printable ASCII excluding the colon that
 * terminates it. Empty is accepted and means "no tracking header".
 */
static int valid_header_name(const char* s) {
  size_t i;

  for (i = 0; s[i] != '\0'; i++) {
    if (s[i] < 33 || s[i] > 126 || s[i] == ':') {
      return 0;
    }
  }
  return 1;
}


/* Returns 0 and sets *out on success, -1 for anything but "1" or "0".
 * Deliberately strict: atoi() would read "true" as 0 and silently disable
 * a target the operator meant to switch on. */
static int parse_bool(const char* value, int* out) {
  if (strcmp(value, "1") == 0) {
    *out = 1;
    return 0;
  }
  if (strcmp(value, "0") == 0) {
    *out = 0;
    return 0;
  }
  return -1;
}


/*
 * Record why a key was rejected and return 0, which stops ini_parse() and
 * makes it report the offending line number. gelf_load_config pairs the two
 * into a single diagnostic.
 */
static int config_error(config_t* pconfig, const char* section,
                        const char* name, const char* detail) {
  /* inih keeps parsing after a handler returns 0 and reports only the FIRST
   * offending line, so keep the first message too or the two would describe
   * different keys. */
  if (pconfig->parse_error[0] == '\0') {
    snprintf(pconfig->parse_error, sizeof(pconfig->parse_error),
             "[%s] %s: %s", section, name, detail);
  }
  return 0;
}


static int gelf_ini_handler(void* user, const char* section, const char* name, const char* value) {
  config_t* pconfig = (config_t*)user;

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
  if (MATCH("logging", "log_source_hostname")) {
    strncpy(pconfig->log_source_hostname, value, sizeof(pconfig->log_source_hostname) - 1);
    pconfig->log_source_hostname[sizeof(pconfig->log_source_hostname) - 1] = '\0';
  }
  else if (MATCH("logging", "verbose")) {
    if (parse_bool(value, &pconfig->verbose) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("logging", "tracking_header")) {
    if (!valid_header_name(value)) {
      return config_error(pconfig, section, name,
                          "expected an RFC 5322 header name without the colon, e.g. X-Submission-ID");
    }
    strncpy(pconfig->tracking_header, value, sizeof(pconfig->tracking_header) - 1);
    pconfig->tracking_header[sizeof(pconfig->tracking_header) - 1] = '\0';
  }
  else if (MATCH("main", "execute_dotqmail")) {
    if (parse_bool(value, &pconfig->execute_dotqmail) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("main", "ensure_homedir_is_set_in_db")) {
    if (parse_bool(value, &pconfig->ensure_homedir_is_set_in_db) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("main", "ensure_homedir_exists_on_disk")) {
    if (parse_bool(value, &pconfig->ensure_homedir_exists_on_disk) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("gelf_log", "enabled")) {
    if (parse_bool(value, &pconfig->gelf.enabled) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("gelf_log", "address")) {
    /* Numeric IPv4 only, no DNS: a resolver call here would sit in the
     * delivery path. Keep the raw value for diagnostics. */
    free((void*)pconfig->gelf.address);
    pconfig->gelf.address = strdup(value);
    if (inet_pton(AF_INET, value, &pconfig->gelf.addr.sin_addr) != 1) {
      return config_error(pconfig, section, name,
                          "expected a dotted IPv4 address, e.g. 127.0.0.1");
    }
    pconfig->gelf.addr.sin_family = AF_INET;
  }
  else if (MATCH("gelf_log", "port")) {
    char* end;
    long port = strtol(value, &end, 10);

    if (*value == '\0' || *end != '\0' || port < 1 || port > 65535) {
      return config_error(pconfig, section, name, "expected a port number 1-65535");
    }
    pconfig->gelf.port = (int)port;
    pconfig->gelf.addr.sin_port = htons((uint16_t)port);
  }
  else if (MATCH("gelf_log", "compression")) {
    if (strcasecmp(value, "gzip") == 0) {
      pconfig->gelf.compression = GELF_COMPRESSION_GZIP;
    } else if (strcasecmp(value, "none") == 0) {
      pconfig->gelf.compression = GELF_COMPRESSION_NONE;
    } else {
      return config_error(pconfig, section, name, "expected gzip or none");
    }
  }
  else if (MATCH("gelf_log", "min_severity")) {
    if (parse_severity(value, &pconfig->gelf.min_severity) != 0) {
      return config_error(pconfig, section, name, "expected one of: " SEVERITY_NAME_LIST);
    }
  }
  else if (MATCH("file_log", "enabled")) {
    if (parse_bool(value, &pconfig->file.enabled) != 0) {
      return config_error(pconfig, section, name, "expected 1 or 0");
    }
  }
  else if (MATCH("file_log", "path")) {
    free((void*)pconfig->file.path); /* replace the default set in gelf_load_config */
    if (value[0] == '/') {
      pconfig->file.path = strdup(value);
    } else {
      /* A relative path is anchored to VPOPMAILDIR, never to the current
       * directory: at delivery time the cwd is the domain directory, so a
       * cwd-relative path would scatter a separate log inside every domain,
       * within the very tree a site may be trying not to write to. */
      char resolved[MAX_BUFF];

      if (snprintf(resolved, sizeof(resolved), "%s/%s", VPOPMAILDIR, value)
          >= (int)sizeof(resolved)) {
        return config_error(pconfig, section, name,
                            "path is too long once anchored to " VPOPMAILDIR);
      }
      pconfig->file.path = strdup(resolved);
    }
  }
  else if (MATCH("file_log", "format")) {
    if (strcasecmp(value, "pretty") == 0) {
      pconfig->file.format = GELF_FORMAT_PRETTY;
    } else if (strcasecmp(value, "gelf") == 0) {
      pconfig->file.format = GELF_FORMAT_GELF;
    } else {
      return config_error(pconfig, section, name, "expected pretty or gelf");
    }
  }
  else if (MATCH("file_log", "min_severity")) {
    if (parse_severity(value, &pconfig->file.min_severity) != 0) {
      return config_error(pconfig, section, name, "expected one of: " SEVERITY_NAME_LIST);
    }
  }
  else {
    return config_error(pconfig, section, name, "unknown key");
  }
#undef MATCH
  return 1;
};


// The file must exist.
// caller must free the strings in config. Returns 0 on success.
/*
 * Load the [main], [gelf_log] and [file_log] sections into 'config'.
 * Zeroes *config first, then applies the documented defaults, so every field
 * is usable whether or not its key appeared. Does not touch any gelf_t fields.
 *
 * [gelf_log] address and port hold the plain human-readable values (handy for
 * logging), while addr is fully populated and ready to hand straight to
 * sendto() (family, address, and port already in network byte order).
 * Wraps inih and libcjson so callers don't need to know about either.
 *
 * The config file defaults to VPOPMAILDIR/etc/vdelivermail.ini
 * (alongside vpopmail's other config files), overridable via the
 * VPOPMAIL_VDELIVERMAIL_CONFIG environment variable.
 *
 * Any malformed value is an error whether or not its target is enabled, so
 * that -t catches a typo before it matters. Callers defer the delivery rather
 * than dropping it, so a bad config file queues mail; it does not lose it.
 *
 * Return: 0 on success, non-zero on error (file open failure, parse error,
 * or [gelf_log] enabled with no address).
 */
int gelf_load_config(config_t *config, int check_mode) {
  char default_path[MAX_BUFF];
  const char* filename = getenv(GELF_CONFIG_ENV);
  int line;

  if (filename == NULL || *filename == '\0') {
    snprintf(default_path, sizeof(default_path), "%s/etc/vdelivermail.ini", VPOPMAILDIR);
    filename = default_path;
  }

  memset(config, 0, sizeof(*config));

  /* Defaults, matching the commented values shipped in vdelivermail.ini. */
  if (gethostname(config->log_source_hostname, sizeof(config->log_source_hostname)) != 0) {
    strcpy(config->log_source_hostname, "unknown");
  }
  /* gethostname() is not required to terminate a truncated name. */
  config->log_source_hostname[sizeof(config->log_source_hostname) - 1] = '\0';

  /* Remedies for an inconsistent account are on unless a site turns them
   * off, e.g. because delivery pipes to LMTP and the homedir is Dovecot's
   * business rather than ours. */
  config->execute_dotqmail = 1;
  config->ensure_homedir_is_set_in_db = 1;
  config->ensure_homedir_exists_on_disk = 1;

  config->gelf.port = 12201;
  config->gelf.addr.sin_port = htons(12201);
  config->gelf.compression = GELF_COMPRESSION_NONE;
  config->gelf.min_severity = LOG_INFO;

  /* Under VPOPMAILDIR rather than /var/log/qmail: a site's logs then live
   * beside everything else vpopmail owns, and a relocated install takes its
   * logs with it. Compile-time concatenation, so there is nothing to truncate. */
  config->file.path = strdup(VPOPMAILDIR "/log/vdelivermail.log");
  config->file.min_severity = LOG_INFO;
  config->file.format = GELF_FORMAT_PRETTY;

  line = ini_parse(filename, gelf_ini_handler, config);
  if (line != 0) {
    if (check_mode) {
      if (line < 0) {
        printf("ERROR: Failed to read config file %s\n", filename); // also missing file
      } else if (config->parse_error[0] != '\0') {
        printf("ERROR: %s (%s line %d)\n", config->parse_error, filename, line);
      } else {
        printf("ERROR: Syntax error in config file %s at line %d\n", filename, line);
      }
    }
    return 1;
  }

  if (config->gelf.enabled && config->gelf.addr.sin_family != AF_INET) {
    if (check_mode) {
      printf("ERROR: [gelf_log] is enabled but no address is set\n");
    }
    return 1;
  }

#ifndef HAVE_ZLIB
  /* Checked after parsing, since enabled may come after compression. A
   * disabled section may say gzip, e.g. the shipped sample. */
  if (config->gelf.enabled && config->gelf.compression == GELF_COMPRESSION_GZIP) {
    if (check_mode) {
      printf("ERROR: [gelf_log] is enabled with compression = gzip, but vdelivermail was built without zlib\n");
    }
    return 1;
  }
#endif

  /*
   * The tracking header is logged under a field named after the header
   * itself, so that every _header_* field means the header it is named for.
   * Derived once here rather than per record.
   */
  if (config->tracking_header[0] != '\0') {
    char snake[128];

    snake_case(config->tracking_header, snake, sizeof(snake));
    if (snake[0] == '\0') {
      if (check_mode) {
        printf("ERROR: [main] tracking_header '%s' has no alphanumeric characters\n",
               config->tracking_header);
      }
      return 1;
    }
    snprintf(config->tracking_field_name, sizeof(config->tracking_field_name), "_header_%s", snake);
  }

  /*
   * Deliberately not opened here: -t is often run as root, and a root-owned
   * log file would then be unwritable by the delivery user. Check the
   * directory the file must live in instead. gelf_setup does the real open.
   */
  if (check_mode && config->file.enabled) {
    char dir[MAX_BUFF];
    char* slash;
    struct stat st;

    snprintf(dir, sizeof(dir), "%s", config->file.path);
    slash = strrchr(dir, '/');
    if (slash == dir) {
      dir[1] = '\0';       /* "/vdelivermail.log" -> "/" */
    } else if (slash != NULL) {
      *slash = '\0';
    } else {
      snprintf(dir, sizeof(dir), ".");
    }

    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
      printf("ERROR: [file_log] directory %s does not exist; it is not created for you\n", dir);
      return 1;
    }

    /* AT_EACCESS tests the effective uid, which is the one that will do the
     * open: under systemd, ExecStartPre runs as User=, so -t there answers
     * the question that matters. Note that running -t as root proves
     * nothing, since root passes regardless of the mode bits. */
    if (faccessat(AT_FDCWD, config->file.path, F_OK, AT_EACCESS) == 0) {
      if (faccessat(AT_FDCWD, config->file.path, W_OK, AT_EACCESS) != 0) {
        printf("ERROR: [file_log] %s is not writable by uid %d\n",
               config->file.path, (int)geteuid());
        return 1;
      }
    } else if (faccessat(AT_FDCWD, dir, W_OK | X_OK, AT_EACCESS) != 0) {
      printf("ERROR: [file_log] %s does not exist and uid %d cannot create it in %s\n",
             config->file.path, (int)geteuid(), dir);
      return 1;
    }
  }

  return 0;
};


/*
 * Open the [file_log] target for append, creating it 0660 if it does not exist.
 * A missing parent directory is not created: that is a configuration error,
 * and gelf_setup's caller defers the delivery rather than losing the record.
 * Returns 0 on success, -1 on failure with errno from open() (umask() doesn't touch it).
 */
static int file_open(gelf_t *gelf) {
  mode_t saved;

  /* 0666 & ~007 == 0660. The inherited umask is whatever qmail-send was
   * started with, so it is overridden here and restored immediately:
   * maildirs and quota files created later must keep the caller's umask.
   * O_CLOEXEC keeps the descriptor out of delivery pipes we exec into. */
  saved = umask(007);
  gelf->log_fd = open(gelf->config.file.path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
  umask(saved);

  return (gelf->log_fd < 0) ? -1 : 0;
}


/*
 * Append one format=gelf record: the same GELF document sent over UDP, on a line
 * of its own. Silent on failure - a full disk must not cost us the delivery,
 * exactly as a failed sendto() does not.
 */
/*
 * cJSON's pretty printer indents with tabs and puts a tab after every colon, and offers no
 * way to change either. Rewrite the structural whitespace as two spaces per level and one
 * space after a key, matching how jq prints. Safe to do textually because cJSON escapes control characters inside
 * strings -- a tab in a value is emitted as the two characters \t -- so every raw tab in its
 * output is structural. Returns a malloc'd string, or NULL.
 */
static char *respace(const char *in) {
  size_t len = strlen(in);
  char *out = malloc(len * 2 + 1); /* each tab grows by at most one character */
  size_t i, o = 0;
  int at_line_start = 1;

  if (out == NULL) {
    return NULL;
  }
  for (i = 0; i < len; i++) {
    if (in[i] == '\t') {
      out[o++] = ' ';
      if (at_line_start) {
        out[o++] = ' '; /* indentation: two spaces per level, as jq prints it */
      }
      continue;         /* a run of indent tabs stays "at line start" */
    }
    out[o++] = in[i];
    at_line_start = (in[i] == '\n');
  }
  out[o] = '\0';
  return out;
}


/*
 * Dropped from format=pretty: fields that exist for the wire, constants, and numbers that a
 * person would rather read as words. Each one either says nothing to a human or is already
 * said better by a neighbour -- _time for timestamp, _severity for level. _vdm_id
 * stays: it is the only thing tying a run's start, delivery and exit together.
 */
static const char *const omit_from_pretty[] = {
  "version",    /* GELF protocol version */
  "host",       /* constant per box */
  "timestamp",  /* epoch; _time carries the same instant in local time */
  "_app",       /* constant */
  "level",      /* number; _severity carries the same thing as a word */
};


static void file_write(gelf_t *gelf, const char* json, size_t json_len) {
  char* line;
  size_t len = json_len + 1;
  size_t off = 0;

  if (gelf->log_fd < 0) {
    return;
  }

  /* One buffer, one write: concurrent deliveries each append a whole record instead of
   * interleaving fragments of two. That is what lets format=pretty span several lines
   * safely -- the record is still a single write() to an O_APPEND fd. */
  line = malloc(len);
  if (line == NULL) {
    return;
  }
  memcpy(line, json, json_len);
  line[json_len] = '\n';

  while (off < len) {
    ssize_t written = write(gelf->log_fd, line + off, len - off);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    off += (size_t)written;
  }
  free(line);
};


#ifdef HAVE_ZLIB
/* Gzip-wrap `in` via zlib (windowBits = 15+16). Caller frees *out on success. */
static int gelf_gzip(const unsigned char* in, size_t in_len,
                     unsigned char** out, size_t* out_len) {
  z_stream strm;
  unsigned char* buf;
  uLong bound;
  int ret;

  memset(&strm, 0, sizeof(strm));
  if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                   15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    return -1;
  }

  bound = deflateBound(&strm, (uLong)in_len);
  buf = malloc(bound);
  if (buf == NULL) {
    deflateEnd(&strm);
    return -1;
  }

  strm.next_in = (Bytef*)in;
  strm.avail_in = (uInt)in_len;
  strm.next_out = buf;
  strm.avail_out = (uInt)bound;

  ret = deflate(&strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    free(buf);
    deflateEnd(&strm);
    return -1;
  }

  *out_len = (size_t)strm.total_out;
  *out = buf;
  deflateEnd(&strm);
  return 0;
}
#endif /* HAVE_ZLIB */


static int gelf_ensure_socket(gelf_t *gelf) {
  if (gelf->sock >= 0) {
    return 0;
  }
  gelf->sock = socket(AF_INET, SOCK_DGRAM, 0);
  return (gelf->sock < 0) ? -1 : 0;
}




/*
 * Render t as RFC 3339 local time into buf, e.g. "2025-12-31T15:23:48+08:00".
 *
 * Local time throughout: localtime_r() calls tzset(), so TZ in the
 * environment selects the zone and TZ=UTC in qmail's run script is all a
 * site needs to log in UTC. The offset is always present because a bare
 * local time is ambiguous across a DST boundary and meaningless to a reader
 * in another zone.
 *
 * The "T" is kept rather than the space RFC 3339 section 5.6 permits, because
 * these fields have to survive being mapped as a date by whoever receives
 * them. Elasticsearch and OpenSearch default a date field to
 * "strict_date_optional_time||epoch_millis", which parses the "T" form and
 * rejects the space form - and a parse failure there discards the whole
 * record, not just the field. One character of readability buys a value a
 * Graylog operator can map with no format string of their own.
 *
 * RFC 3339 requires the colon in the offset. strftime's %z yields "+0800"
 * with no colon, and there is no portable conversion that supplies one - %:z
 * is a date(1) feature, not a strftime one - so it is inserted by hand.
 */
static void format_rfc3339_local(char* buf, size_t len, time_t t) {
  struct tm tm;
  size_t n;

  buf[0] = '\0';
  if (localtime_r(&t, &tm) == NULL) {
    return;
  }

  n = strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", &tm);
  if (n == 0) {
    buf[0] = '\0';
    return;
  }

  /* "...+0800" -> "...+08:00", if an offset was actually produced. */
  if (n >= 5 && (buf[n - 5] == '+' || buf[n - 5] == '-') && n + 1 < len) {
    buf[n + 1] = '\0';
    buf[n]     = buf[n - 1];
    buf[n - 1] = buf[n - 2];
    buf[n - 2] = ':';
  }
}


/*
 * Create an empty GELF JSON root.
 * Returns NULL if logging is disabled or allocation fails - callers may pass
 * the NULL straight on, since cJSON_Add*ToObject and gelf_send both tolerate
 * it. On success the caller must pass the object to gelf_send() (which frees
 * it) or call cJSON_Delete() to discard it.
 *
 * Emits no fields of its own: each emitter decides its own field order, then
 * calls add_common_fields() just before gelf_send().
 */
static cJSON *gelf_begin(gelf_t *gelf) {
  if (gelf == NULL || !(gelf->config.gelf.enabled || gelf->config.file.enabled))
    return NULL;

  return cJSON_CreateObject();
}


/* Add one RFC 3339 local-time field, e.g. "_time" or "_time_sent". */
static void add_local_time(cJSON *root, const char *name, time_t t) {
  char timebuf[40];

  format_rfc3339_local(timebuf, sizeof(timebuf), t);
  cJSON_AddStringToObject(root, name, timebuf);
}


/* Add name (e.g. "_header_from_address") holding the address extracted from
 * a decoded From or Sender value, or nothing if extraction fails. */
static void add_header_address(cJSON *root, const char *name, const char *value) {
  char address[HEADER_VALUE_MAX];

  if (extract_address(value, address, sizeof(address))) {
    cJSON_AddStringToObject(root, name, address);
  }
}


/*
 * Open a record with when it happened, what kind it is, and how bad it is, then return the
 * time_t behind the date so the caller can hand the same value to add_common_fields(). Two
 * calls to time() could otherwise straddle a second boundary and leave _time and
 * timestamp disagreeing.
 *
 * Called first by each emitter, so a line opens with a readable date, and _event and
 * _severity land ahead of even short_message: between them they tell a reader whether this
 * record is worth their attention and which other fields to expect -- a delivery record and
 * an exit record share almost nothing below this point. Emitted here rather than left to each
 * builder so the ordering cannot drift.
 *
 * "level" is GELF's own field and a number by specification; _severity is the same value as
 * the word min_severity accepts in the ini, since both directions read severity_names[]. Both
 * go to every target: format=pretty drops the number, and a person reading format=gelf with jq
 * wants the word as much as a person reading pretty does. They are written adjacent so the
 * pair cannot be read as two different things.
 *
 * event may be NULL for a record that has no kind of its own.
 */
static time_t add_time_and_event(cJSON *root, const char *event, int severity) {
  const char *name = severity_name(severity);
  time_t now = time(NULL);

  add_local_time(root, "_time", now);
  if (event != NULL) {
    cJSON_AddStringToObject(root, "_event", event);
  }
  cJSON_AddNumberToObject(root, "level", severity);
  if (name != NULL) {
    cJSON_AddStringToObject(root, "_severity", name);
  }
  return now;
}


/*
 * Emit the fields every GELF record carries. Called by each emitter as its
 * last act before gelf_send(), which puts the boilerplate at the tail of the
 * line where it does not obstruct reading the interesting fields.
 * 'now' must be the value returned by add_time_and_event().
 */
static void add_common_fields(gelf_t *gelf, cJSON *root, time_t now) {
  cJSON_AddStringToObject(root, "version", "1.1");
  cJSON_AddStringToObject(root, "host", gelf->config.log_source_hostname);
  /* GELF timestamp: whole seconds since the epoch, matching the epoch in
   * vdm_id. Supplied rather than left to Graylog's receive time, and zone
   * free by construction, unlike _time. */
  cJSON_AddNumberToObject(root, "timestamp", (double)now);
  cJSON_AddStringToObject(root, "_app", "vdelivermail");
  cJSON_AddStringToObject(root, "_vdm_id", gelf->vdm_id);
}


/* Parse an RFC 5322 Date value into seconds since Unix epoch.
 * Returns 0 on success and writes *timestamp_out; -1 if date is
 * NULL, empty, or unparseable (*timestamp_out is left unchanged). */
#ifdef HAVE_CURL_GETDATE
static int calc_timestamp(const char *date, time_t *timestamp_out) {
  time_t mail_ts;

  if (date == NULL || date[0] == '\0') {
    return -1;
  };

  mail_ts = curl_getdate(date, NULL);
  if (mail_ts == (time_t)-1) {
    return -1;
  };

  *timestamp_out =(time_t)mail_ts;
  return 0;
}
#endif /* HAVE_CURL_GETDATE */


/*
 * Fields derived from the message's Date: header.
 *
 * Emits nothing at all unless a date is present and usable, so that a query
 * on _time_sent never has to reason about deliveries where it happens to be
 * missing. _header_date is the unparsed header and exists only as the
 * fallback for builds without libcurl; where _time_sent is available it is not
 * emitted, so nobody is tempted to query the string instead of the number.
 */
/*
 * The date at the tail of qmail-queue's Received line:
 *   "(qmail 12345 invoked from network); 26 Sep 2026 10:23:45 -0000"
 * It follows the last "; ". Nothing earlier in that line contains one, and
 * taking the last occurrence is safe even if a future qmail adds more.
 * Returns NULL when there is no such separator.
 */
static const char *received_date(const char *value) {
  const char *found = NULL;
  const char *s;

  for (s = value; (s = strstr(s, "; ")) != NULL; s += 2) {
    found = s + 2;
  }
  return found;
}


/*
 * Emit when the message entered the queue, from the topmost Received.
 * Unlike _time this does not move across defers -- the queue file is written
 * once at injection -- so _time minus _time_queued is how long delivery has
 * been retrying. Emits nothing at all if the topmost Received is not the line
 * qmail-queue writes, rather than guessing at an unfamiliar format.
 */
static void add_received_timestamp(cJSON *root, const char *received) {
  const char *datestr;

  if (received == NULL || received[0] == '\0') {
    return;
  }
  datestr = received_date(received);
  if (datestr == NULL || *datestr == '\0') {
    return;   /* not the line we expect: emit nothing rather than guess */
  }

#ifdef HAVE_CURL_GETDATE
  {
    time_t epoch;

    if (calc_timestamp(datestr, &epoch) == 0) {
      add_local_time(root, "_time_queued", epoch);
    }
  }
#else
  /* No curl_getdate to turn it into an epoch, so log the date component
   * verbatim. Could be any format or timezone qmail-queue happened to emit.
   *
   * Deliberately inside the #else and not a runtime fallback: on a build with
   * curl, a Received line we cannot parse yields no field at all. A receiver
   * that has mapped _time_queued as a date rejects the entire record on a value
   * it cannot parse, so an unparsed date must never reach the same field name
   * as a parsed one -- nor may its presence depend on the message, or half a
   * site's records would carry a field the other half does not. */
  cJSON_AddStringToObject(root, "_time_queued_raw", datestr);
#endif
}


static void add_message_timestamp(cJSON *root, const char *date) {
  if (date == NULL || date[0] == '\0') {
    return;
  }

#ifdef HAVE_CURL_GETDATE
  {
    time_t date_epoch;

    if (calc_timestamp(date, &date_epoch) == 0) {
      add_local_time(root, "_time_sent", date_epoch);
    }
  }
#else
  /* Same rule as _time_queued_raw above: a no-curl build only, never a runtime
   * fallback beside _time_sent. */
  cJSON_AddStringToObject(root, "_header_date", date);
#endif
}


/*
 * Add the bulk RFC 5322 header fields to an open GELF root object.
 * _header_subject, _header_message_id and the Date-derived fields are not
 * here:
 * every emitter places those itself, subject near the front and the dates
 * at the very end of the record.
 */
static void gelf_add_headers(cJSON *root, const message_headers_t *h) {
  /* _header_from is deliberately not here: log_exit emits it earlier, beside
   * _header_sender, because the two are only meaningful together. */
  /* _header_to and _header_cc are deliberately not logged: the envelope _to is
   * what determined delivery, and neither header contains the recipient for
   * list, Bcc or aliased mail -- so searching on them misleads. */
  if (h->x_spam_status[0])
    cJSON_AddStringToObject(root, "_header_x_spam_status", h->x_spam_status);
  if (h->authentication_results[0])
    cJSON_AddStringToObject(root, "_header_authentication_results", h->authentication_results);
}


/*
 * Serialize root to JSON once and hand it to every enabled target that wants
 * a record of this severity: [file_log] as one line, [gelf_log] gzipped or not
 * over UDP. Frees root either way.
 */
static void gelf_send(gelf_t *gelf, cJSON *root) {
  char *json;
  unsigned char *gz;
  size_t gz_len;
  size_t json_len;
  cJSON *level;
  cJSON *event;
  char event_name[32] = "";
  int severity = LOG_INFO;
  int want_file, want_gelf;
  static int reporting_drop;

  /* Every caller sets "level" before we get here; a record without one is
   * treated as info rather than silently discarded. Lower is more severe, so
   * a target drops a record whose level is numerically above its threshold. */
  level = cJSON_GetObjectItemCaseSensitive(root, "level");
  if (cJSON_IsNumber(level)) {
    severity = level->valueint;
  }

  want_file = gelf->config.file.enabled && severity <= gelf->config.file.min_severity;
  want_gelf = gelf->config.gelf.enabled && severity <= gelf->config.gelf.min_severity;

  /* Pretty output is the file's alone, so it gets its own rendering. Everything else shares
   * the compact one: the wire has a size cap, and a file asking for format=gelf wants exactly what
   * the wire wants. */
  /* format=pretty is for a person reading the file, so strip what only the wire needs. The
   * duplicate is because root still has to reach the [gelf_log] target intact. format=gelf keeps
   * everything, on the grounds that a file in that shape exists to be shipped somewhere. */
  if (want_file && gelf->config.file.format == GELF_FORMAT_PRETTY) {
    cJSON *readable = cJSON_Duplicate(root, 1);
    cJSON *item;
    char *pretty;
    size_t f;

    if (readable == NULL) {
      cJSON_Delete(root);
      return;
    }
    for (f = 0; f < sizeof omit_from_pretty / sizeof *omit_from_pretty; f++) {
      cJSON_DeleteItemFromObjectCaseSensitive(readable, omit_from_pretty[f]);
    }
    /* GELF requires the leading underscore on every custom field; a person reading a file
     * does not. Shift each key left over its own '_' -- in place, because the name only ever
     * gets shorter, so there is no allocation and nothing to free. Safe from collisions while
     * no unprefixed key shares a name with a stripped one (today: short_message, full_message
     * and level, none of which has an _-prefixed twin). */
    for (item = readable->child; item != NULL; item = item->next) {
      if (item->string != NULL && item->string[0] == '_' && item->string[1] != '\0') {
        memmove(item->string, item->string + 1, strlen(item->string));
      }
    }
    pretty = cJSON_Print(readable);
    cJSON_Delete(readable);

    if (pretty != NULL) {
      char *spaced = respace(pretty);

      if (spaced != NULL) {
        file_write(gelf, spaced, strlen(spaced));
        free(spaced);
      }
      cJSON_free(pretty);
    }
    want_file = 0;
  }

  if (!want_file && !want_gelf) {
    cJSON_Delete(root);
    return;
  }

  /* No field is dropped here: every target gets the same fields, which is what keeps
   * format=gelf byte-identical to the datagram, which is what the name promises.
   * Only format=pretty differs, by removing omit_from_pretty[] from its own copy above. */
  event = cJSON_GetObjectItemCaseSensitive(root, "_event");
  if (cJSON_IsString(event)) {
    snprintf(event_name, sizeof(event_name), "%s", event->valuestring);
  }

  json = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (json == NULL)
    return;

  json_len = strlen(json);

  if (want_file) {
    file_write(gelf, json, json_len);
  }

  if (!want_gelf) {
    cJSON_free(json);
    return;
  }

#ifdef HAVE_ZLIB
  /* Without zlib, config loading rejects an enabled [gelf_log] with
   * compression = gzip, so this is the only branch that ever needs it. */
  if (gelf->config.gelf.compression == GELF_COMPRESSION_GZIP) {
    /* Probably out of memory on failure, but there's no safe place to log. */
    if (gelf_gzip((const unsigned char*)json, json_len, &gz, &gz_len) != 0) {
      cJSON_free(json);
      return;
    }
    cJSON_free(json);
    json = NULL; /* ownership transferred to gz (malloc) */
  } else
#endif
  {
    gz = (unsigned char*)json;
    gz_len = json_len;
  }

  if (gz_len > GELF_UDP_MAX) {
    if (json != NULL)
      cJSON_free(json);
    else
      free(gz);
    /* The warning is a small record, so it fits. The guard stops a warning
     * that somehow didn't fit from recursing. */
    if (!reporting_drop) {
      char msg[160];
      reporting_drop = 1;
      snprintf(msg, sizeof(msg),
               "GELF %s record dropped: %zu bytes exceeds the %d-byte UDP limit",
               event_name[0] ? event_name : "(unknown)", gz_len, GELF_UDP_MAX);
      gelf_log(gelf, LOG_WARNING, msg, NULL);
      reporting_drop = 0;
    }
    return;
  }

  if (gelf_ensure_socket(gelf) != 0) {
    if (json != NULL)
      cJSON_free(json);
    else
      free(gz);
    return;
  }

  /* gelf.addr already has family, address, and port from config load */
  (void)sendto(gelf->sock, gz, gz_len, 0,
               (struct sockaddr*)&gelf->config.gelf.addr,
               sizeof(gelf->config.gelf.addr));

  if (json != NULL)
    cJSON_free(json);
  else
    free(gz);
}


/* Generic log: base fields only (no message headers, no event). */
/*
 * Generic log: base GELF fields only (version/host/short_message/level/
 * _app).  No message headers, no _event.  Use when you have no
 * delivery or exit context to attach.
 * No-op if gelf is NULL or logging is disabled. Failures are silent.
 * Callers pass an RFC 5424 severity (0=emerg .. 7=debug).
 * full_message may be NULL or "", either of which omits the field.
 */
void gelf_log(gelf_t *gelf, int severity, const char *buf, const char *full_message) {
  cJSON *root = gelf_begin(gelf);
  time_t now = add_time_and_event(root, NULL, severity);

  cJSON_AddStringToObject(root, "short_message", buf);

  if (full_message && full_message[0]) {
    cJSON_AddStringToObject(root, "full_message", full_message);
  }

  /* Guarded as in log_process_start: gelf_log can fire at any point, so none
   * of these are certain to be populated yet. */
  if (gelf->context.to[0]) {
    cJSON_AddStringToObject(root, "_to", gelf->context.to);
  }

  if (gelf->context.from_known) {
    cJSON_AddStringToObject(root, "_from", gelf->context.from);
  }

  /* An empty subject must mean the sender sent an empty one (or none), or
   * that it was too long to log (a warning says so), not that we had not
   * yet looked. */
  if (gelf->context.headers_extracted) {
    cJSON_AddStringToObject(root, "_header_subject", gelf->context.headers.subject);
    /* Correlation keys: logged on every record so that one message can be
     * followed across qmail-smtpd, qmail-send, vdelivermail and beyond. */
    if (gelf->context.headers.message_id[0]) {
      cJSON_AddStringToObject(root, "_header_message_id", gelf->context.headers.message_id);
    }
    if (gelf->context.headers.tracking_header[0]) {
      cJSON_AddStringToObject(root, gelf->config.tracking_field_name, gelf->context.headers.tracking_header);
    }
  }

  if (gelf->context.domain[0]) {
    cJSON_AddStringToObject(root, "_domain", gelf->context.domain);
  }

  add_common_fields(gelf, root, now);

  if (gelf->context.headers_extracted) {
    add_message_timestamp(root, gelf->context.headers.date);
  }

  gelf_send(gelf, root);
}


// from/to could be absent due to missing or invalid environment variables
// OriginalDomain is apparent in the "to" field after the @ sign.
void log_process_start(gelf_t *gelf) {
  char cwd[PATH_MAX];
  char short_message[1024];

  cJSON *root = gelf_begin(gelf);
  time_t now = add_time_and_event(root, "start", LOG_INFO);

  sprintf(short_message, "Loading mail from %s", gelf->context.from);
  cJSON_AddStringToObject(root, "short_message", short_message);

  if (gelf->context.to[0]) {
    cJSON_AddStringToObject(root, "_to", gelf->context.to);
  }

  if (gelf->context.from_known) {
    cJSON_AddStringToObject(root, "_from", gelf->context.from);
  }

  // domain may or may not be available, based on when log_process_start is called.
  if (gelf->context.domain[0]) {
    cJSON_AddStringToObject(root, "_domain", gelf->context.domain);
  }

  // When run under .qmail-default, the current directory implies the dealiased domain.
  // Resolved from the dentry cache, so this cannot block on a stalled mount.
  // We won't log getwcd errors.
  // If we moved log_process_start before get_environment, this log field would be
  // the easiest way to deduce the dealiased domain.
  if (getcwd(cwd, sizeof cwd) != NULL) {
    // cJSON_AddStringToObject(root, "_current_directory", cwd);
  }

  add_common_fields(gelf, root, now);
  gelf_send(gelf, root);
}


const char *quota_calc_source_name(int source) {
  switch (source) {
    case QUOTA_CALC_DAEMON: return "daemon";
    case QUOTA_CALC_MAILDIRSIZE_CACHED: return "maildirsize_cached";
    case QUOTA_CALC_MAILDIRSIZE_RECALC: return "maildirsize_recalc";
    default: return "other";
  }
}

/*
 * Emit a GELF "delivery" event from gelf->context.delivery (and headers).
 * short_message comes from delivery.message; level is INFO.
 * No-op if gelf is NULL or logging is disabled. Failures are silent.
 * Fields that are zero/empty/false are omitted where appropriate;
 * _code is emitted only when delivery.has_exit_status is set;
 * _signal is emitted only when delivery.has_signal is set.
 */
void log_delivery(gelf_t *gelf,delivery_log_t* d) {
  //delivery_log_t *d = &gelf->context.delivery;
  cJSON *root = gelf_begin(gelf);
  time_t now = add_time_and_event(root, "delivery", LOG_INFO);

  cJSON_AddStringToObject(root, "short_message", d->message);
  cJSON_AddStringToObject(root, "_to", gelf->context.to);
  cJSON_AddStringToObject(root, "_from", gelf->context.from);

  // TODO: Consider not sending if Subject omitted, rather than just being empty string.
  if (gelf->context.headers_extracted) {
    cJSON_AddStringToObject(root, "_header_subject", gelf->context.headers.subject);
    /* Correlation keys: logged on every record so that one message can be
     * followed across qmail-smtpd, qmail-send, vdelivermail and beyond. */
    if (gelf->context.headers.message_id[0]) {
      cJSON_AddStringToObject(root, "_header_message_id", gelf->context.headers.message_id);
    }
    if (gelf->context.headers.tracking_header[0]) {
      cJSON_AddStringToObject(root, gelf->config.tracking_field_name, gelf->context.headers.tracking_header);
    }
  }

  cJSON_AddStringToObject(root, "_domain", gelf->context.domain); // or use getenv

  if (gelf->context.user[0]) {
    cJSON_AddStringToObject(root, "_user", gelf->context.user);
  }

  cJSON_AddStringToObject(root, "_instruction", d->instruction);
  cJSON_AddStringToObject(root, "_source", d->source);
  cJSON_AddStringToObject(root, "_method", d->method);
  cJSON_AddNumberToObject(root, "_success", d->success ? 1 : 0); // GELF doesn't have bools
  if (d->has_exit_status) {
    cJSON_AddNumberToObject(root, "_code", d->code);
  }
  if (d->has_signal) {
    cJSON_AddNumberToObject(root, "_signal", d->signal);
  }

  //cJSON_AddStringToObject(root, "_message_id", gelf->context.message_id);

  if (d->method && strcmp(d->method, "maildir") == 0) {
    if (d->maildir_path[0])
      cJSON_AddStringToObject(root, "_maildir_path", d->maildir_path);
    if (d->maildir_owner[0])
      cJSON_AddStringToObject(root, "_maildir_owner", d->maildir_owner);

    /* Not inside the quota block below: a delivery has a file size whether or not a quota
     * was in play. 0 means it was never populated -- the message was discarded, or the
     * delivery failed before the file was stat()ed. */
    if (d->maildir_file_size_bytes) {
      cJSON_AddNumberToObject(root, "_maildir_file_size_bytes", d->maildir_file_size_bytes);
    }

    if (strlen(d->maildir_quota_source)) {
      cJSON_AddStringToObject(root, "_maildir_quota_source", d->maildir_quota_source);
      cJSON_AddNumberToObject(root, "_maildir_quota_allocated_bytes",d->maildir_quota_allocated_bytes);
      if (d->maildir_initial_bytes) {
        cJSON_AddNumberToObject(root, "_maildir_initial_bytes",d->maildir_initial_bytes); // quota consumed pre-delivery
      }
      if (d->maildir_quota_initial_bytes_source) {
        cJSON_AddStringToObject(root, "_maildir_quota_initial_bytes_source", quota_calc_source_name(d->maildir_quota_initial_bytes_source));
        /* Milliseconds are plenty; unrounded, cJSON's %.15g would print nanosecond noise. */
        cJSON_AddNumberToObject(root, "_maildir_quota_check_duration",
                                round(d->maildir_quota_check_duration * 1000) / 1000);
      }

      if (d->maildir_quota_initial_bytes_source) {
        cJSON_AddNumberToObject(root, "_maildir_not_enough_space", d->maildir_not_enough_space ? 1 : 0);
        /* Only evaluated once the message is in the maildir, so a failed delivery leaves it
         * unset rather than false. */
        if (d->success) {
          cJSON_AddNumberToObject(root, "_maildir_nearly_full", d->maildir_nearly_full ? 1 : 0);
        }
      }
      cJSON_AddNumberToObject(root, "_maildir_quota_warning_delivered", d->maildir_quota_warning_delivered ? 1 : 0);
        // i.e. delivered warning message to the recipient
    };
  };

  add_common_fields(gelf, root, now);

  if (gelf->context.headers_extracted) {
    add_message_timestamp(root, gelf->context.headers.date);
  }

  gelf_send(gelf, root);
}


// result_size - 12 bytes holds any int.
void calc_human_result(char *result_out, size_t result_size, int code) {
  const char *name = NULL;
  switch (code) {
    case EXIT_OK:      name = "ok"; break;
    case EXIT_BOUNCE:  name = "bounce"; break;
    case EXIT_DEFER:   name = "defer"; break;
    case EXIT_OK_STOP: name = "ok_stop"; break;
  }
  if (name) snprintf(result_out, result_size, "%s", name);
  else snprintf(result_out, result_size, "%d", code);
}


/* TODO: add exit-specific fields from gelf->context once an exit_log_t is defined. */
/*
 * Emit a GELF "exit" event: base fields + RFC 5322 headers.
 * Exit-specific fields will be added once an exit_log_t is defined in
 * gelf_context_t.
 */
// qms_message - some portion of the string that the caller *already* sent to qmail-send's log stream. We don't print it to stdout here.
//     Unlike vexiterr, log_exit won't convert "" to the default message for the given "code" arg. 
//     Both NULL and "" will cause the qmail_log_message field to be omitted from the GELF output.
//     Callers should avoid passing entire bounce messages here. The first 70 characters or so is ample.
void log_exit(gelf_t *gelf, int code, bool success, int severity, const char *qms_message, const char *buf) {
  char human_result[12];
  calc_human_result(human_result, sizeof human_result, code);

  cJSON *root = gelf_begin(gelf);
  time_t now = add_time_and_event(root, "exit", severity);

  cJSON_AddStringToObject(root, "short_message", buf);
  cJSON_AddStringToObject(root, "_to", gelf->context.to); // i.e. OriginalRecipoient not DealiasedRecipient, empty if get_arguments didn't complete
  cJSON_AddStringToObject(root, "_from", gelf->context.from); // empty if get_arguments didn't complete

  if (gelf->context.headers_extracted) {
    cJSON_AddStringToObject(root, "_header_subject", gelf->context.headers.subject);
    
    if (gelf->context.headers.from[0]) {
      add_header_address(root, "_header_from_address", gelf->context.headers.from);
    }
    if (gelf->context.headers.sender[0]) { // rare. Mailing lists and Outlook "on behalf of"
      cJSON_AddStringToObject(root, "_header_sender", gelf->context.headers.sender);
      add_header_address(root, "_header_sender_address", gelf->context.headers.sender);
    }

    /* Correlation keys: logged on every record so that one message can be
     * followed across qmail-smtpd, qmail-send, vdelivermail and beyond. */
    if (gelf->context.headers.message_id[0]) {
      cJSON_AddStringToObject(root, "_header_message_id", gelf->context.headers.message_id);
    }
    if (gelf->context.headers.tracking_header[0]) {
      cJSON_AddStringToObject(root, gelf->config.tracking_field_name, gelf->context.headers.tracking_header);
    }
  }

  cJSON_AddStringToObject(root, "_domain", gelf->context.domain);

  if (gelf->context.user[0]) {
    cJSON_AddStringToObject(root, "_user", gelf->context.user); // the user record delivered into (name@domain), not the address addressed
  }

  if (gelf->context.size_known) {
    cJSON_AddNumberToObject(root, "_size_bytes", gelf->context.size_bytes);
  }

  cJSON_AddStringToObject(root, "_result", human_result);
  cJSON_AddNumberToObject(root, "_success", success);
  cJSON_AddNumberToObject(root, "_code", code);
  cJSON_AddNumberToObject(root, "_is_looping", gelf->context.is_looping ? 1 : 0);

  if (gelf->context.valias_count > 0) {
    cJSON_AddNumberToObject(root, "_valias_count", gelf->context.valias_count);
    cJSON_AddNumberToObject(root, "_valias_completed", gelf->context.valias_completed);
  }
  /* Separately, so that valias lines that are all comments (count 0: delivery
   * silently disabled) still show what they were. */
  if (gelf->context.valias_instructions[0]) {
    cJSON_AddStringToObject(root, "_valias_instructions", gelf->context.valias_instructions);
  }

  cJSON_AddNumberToObject(root, "_user_not_found", gelf->context.user_not_found ? 1 : 0);
  cJSON_AddNumberToObject(root, "_bounced", code == EXIT_BOUNCE ? 1 : 0);

  if (gelf->context.headers_extracted) {
    gelf_add_headers(root, &gelf->context.headers);
  }

  /* Only the loop-detection paths set this, so it is empty on most exits. GELF treats
   * full_message as optional, so omit it rather than emitting "". */
  if (gelf->context.exit_full_message[0]) {
    cJSON_AddStringToObject(root, "full_message", gelf->context.exit_full_message);
  }

  if (qms_message && qms_message[0]) {
    // qmail-send logs up to 3000 bytes of our stdout, but squishes it into a single line by replacing newlines with "/" and spaces with "_".
    cJSON_AddStringToObject(root, "_qmailsend_log_message", qms_message);
  }

  add_common_fields(gelf, root, now);

  if (gelf->context.headers_extracted) {
    add_received_timestamp(root, gelf->context.headers.received);
    add_message_timestamp(root, gelf->context.headers.date);
  }

  gelf_send(gelf, root);
}




// {unixtime}.{pid}.{box}
// box comes from gelf.config.log_source_hostname
void set_vdm_id(gelf_t *gelf) {
  const char *box;

  box = gelf->config.log_source_hostname;
  if (box[0] == '\0')
    box = "unknown";

  snprintf(gelf->vdm_id, sizeof(gelf->vdm_id), "%ld.%ld.%s",
           (long)time(NULL), (long)getpid(), box);
}


/*
 * Loads the logging configuration and opens the [file_log] target.
 * Returns 0 on success, 1 on failure with a one-line reason (no trailing newline or full
 * stop) written to reason_out; reason_out is "" on success.
 *
 * Under qmail the caller defers, and is expected to print the reason to stdout so that it
 * reaches qmail-send's log -- the only place an admin will see it when our own log is what's
 * broken. Beware that stdout is also the text qmail-send puts in the bounce, should the
 * message reach the end of its queue lifetime. So it may name a path and an errno, but nothing more private.
 */
int gelf_setup(gelf_t *gelf, char *reason_out, size_t reason_size) {
  memset(gelf, 0, sizeof(*gelf));
  gelf->sock = -1;
  gelf->log_fd = -1;
  reason_out[0] = '\0';

  if (gelf_load_config(&gelf->config, 0) != 0) {
    snprintf(reason_out, reason_size, "Logging system failed to start"); // TODO: indicate filename
    return 1;
  }

  /* A log file we cannot open at startup is a configuration error, and the
   * caller defers. A write that fails later is ignored: see file_write. */
  if (gelf->config.file.enabled && file_open(gelf) != 0) {
    snprintf(reason_out, reason_size, "Unable to open log file %s: %s",
             gelf->config.file.path, strerror(errno));
    return 1;
  }

  set_vdm_id(gelf);

  return 0;
}