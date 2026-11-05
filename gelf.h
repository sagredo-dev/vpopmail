#ifndef GELF_H
#define GELF_H

#include <stdbool.h>
#include <sys/types.h>

#define STANDARD_DEFER_MESSAGE "Temporary system error. (#4.3.0)"
#define STANDARD_BOUNCE_MESSAGE "Permanent failure. (#5.3.0)"

/* Maximum size of the full message stored in the exit log. */
#define FULL_MESSAGE_MAX 4096

/* [file_log] layouts. Same fields either way -- this only chooses the serialisation. */
#define GELF_FORMAT_PRETTY 0
#define GELF_FORMAT_GELF   1

/*
 * [file_log] - GELF records written to a local file.
 * format=pretty (the default) indents them for readability;
 * format=gelf writes one compact JSON object per line.
 * min_severity is an RFC 5424 severity (0=emerg .. 7=debug); a record is written
 * when its level is that severity or more severe, i.e. level <= min_severity.
 */
typedef struct {
  int enabled;                   /* default 0 */
  int mandatory;                 /* default 1: defer the delivery if the file can't be opened */
  const char* path;              /* default VDELIVERMAIL_LOG_DIR/vdelivermail.log; a relative
                                  * value in the ini is anchored to VPOPMAILDIR */
  int min_severity;              /* default LOG_INFO (6) */
  int format;                    /* GELF_FORMAT_*; default PRETTY */
} file_target_t;

typedef struct {
  char log_source_hostname[256];    /* defaults to gethostname(); empty keeps that */
  int verbose;                      /* default 0 */
  char tracking_header[128];        /* RFC 5322 field name, no colon; empty = disabled */
  char tracking_field_name[160];    /* GELF field name derived from it, e.g. _header_x_submission_id */
  int execute_dotqmail;             /* default 1 */
  int ensure_homedir_is_set_in_db;  /* default 1 */
  int ensure_homedir_exists_on_disk; /* default 1 */
  file_target_t file;
  char parse_error[256];            /* why the handler rejected a key; "" if it did not */
} config_t;

/*
 * Truncated plaintext copies of selected RFC 5322 headers for GELF logging.
 * Each field holds at most HEADER_VALUE_MAX-1 bytes plus a NUL terminator.
 * An empty string means the header was absent or not recognised.
 * Duplicate occurrences of the same header name are ignored (first wins).
 * RFC 2047 encoded-words are stored as-is without decoding.
 */
#include "header_text.h"   /* HEADER_VALUE_MAX */
typedef struct {
  char subject[HEADER_VALUE_MAX];
  char from[HEADER_VALUE_MAX]; // "From:" header inside the message. Relevant for DMARC alingment checks. Outlook "on behalf of", gmail "via"
  char to[HEADER_VALUE_MAX]; // "To:" header inside the message, perhaps including display name, could be multiple recipient addresses.
  char cc[HEADER_VALUE_MAX];
  char date[HEADER_VALUE_MAX];
  char x_spam_status[HEADER_VALUE_LONG_MAX];
  
  /* The topmost Received, which qmail-queue prepends at injection:
   * "(qmail <pid> invoked from network); <date822>". Fixed for the life of
   * the queue entry, so unlike _time it does not move across defers --
   * the difference between the two is how long delivery has been retrying.
   * "invoked from network|by alias|for bounce|by uid N" comes from the
   * invoking process's uid, so a sender cannot influence it. */
  // e.g. Received: (qmail 24220 invoked by uid 5089); 16 Oct 2024 01:25:38 -0000
  // The date is generated just after the SMTP client sends "DATA", and before the server says "354 go ahead".
  char received[HEADER_VALUE_LONG_MAX];

  /* RFC 8601 spf=/dkim=/dmarc= verdicts. Every relay prepends its own, so
   * this is the topmost instance -- which on a qmail that emits one is ours,
   * because qmail-queue writes it at injection, after any upstream hop.
   * Compare its leading authserv-id against control/authservid to be sure. */
  /* e.g.
  Authentication-Results: plesk2.example.com.au;
        spf=pass (sender IP is 91.200.12.133) smtp.mailfrom=no_reply_support@trust-provider.com smtp.helo=ssmail3.sec.dc.comodoca.net
        */
  char authentication_results[HEADER_VALUE_LONG_MAX];
  
  char message_id[HEADER_VALUE_MAX];
  char sender[HEADER_VALUE_MAX]; // Usually absent. For explaining why Outlook shows "on behalf of" 

  // Value of the header named by main.tracking_header in vdelivermail.ini.
  // e.g. X-Submission-Id, gets logged as _header_x_submission_id.
  char tracking_header[HEADER_VALUE_MAX];
} message_headers_t;


typedef struct {
  bool in_progress;
  char message[HEADER_VALUE_MAX];
  char instruction[HEADER_VALUE_MAX];
  const char *source;
  const char *method;
  bool success;
  int code;
  int signal;
  char maildir_path[HEADER_VALUE_MAX];
  char maildir_owner[HEADER_VALUE_MAX];
  char maildir_quota_source[HEADER_VALUE_MAX];
  int64_t maildir_quota_allocated_bytes;
  ssize_t maildir_initial_bytes;
  int maildir_quota_initial_bytes_source; // QUOTA_CALC_* from maildirquota.h
  double maildir_quota_check_duration;
  bool maildir_not_enough_space;
  bool maildir_nearly_full;
  bool maildir_quota_warning_delivered;
  ssize_t maildir_file_size_bytes;
  pid_t pid;
  bool has_exit_status;
  bool has_signal;
} delivery_log_t;

/* Size in bytes (including the NUL) of the exit log's copy of the valias
 * lines. This limits only what is logged: the number of valias lines is
 * unlimited, and all of them are processed. Sized for about 20-30 Maildir
 * paths, since when one line fails the later ones never run and leave no
 * delivery records, so this field is their only trace. Lines that don't
 * fit are replaced by "...". */
#define LOG_VALIAS_INSTRUCTIONS_LENGTH 2048

typedef struct {
  char domain[HEADER_VALUE_MAX]; // after dealiasing, we've already arrived at .qmail-default
  char from[HEADER_VALUE_MAX]; // envelope sender, before dealiasing. getenv(SENDER) or RPLINE=>ReturnPath
  bool from_known; // distinguish unknown (bad RPLINE) from say, bounce messages, with empty string
  char to[HEADER_VALUE_MAX]; // envelope recipient, before dealiasing
  message_headers_t headers;
  delivery_log_t delivery;
  char user[HEADER_VALUE_MAX]; // vpopmail user after vauth_getpw
  char exit_full_message[FULL_MESSAGE_MAX]; // only used for exit log, otherwise we'd need a mechanism to clear it. Other events use log_detailed_event()
  ssize_t size_bytes; // -1 for noquota
  bool size_known;
  bool headers_extracted;   /* caller sets this after extract_headers() */
  bool is_looping;
  int valias_count;
  int valias_completed;
  char valias_instructions[LOG_VALIAS_INSTRUCTIONS_LENGTH];
  bool user_not_found;
  bool catchall; // user not found, attempted catchall delivery instruction
} gelf_context_t;

/*
 * Logger object: ini config plus the long-lived runtime state that would
 * otherwise sit in gelf.c statics. Caller owns the struct and passes it to
 * gelf_log. headers start empty; typically filled by vdelivermail.c's
 * extract_headers().
 */
typedef struct {
  config_t config;
  int log_fd;                    /* [file_log] target; -1 until opened by start_logging */
  char vdm_id[HEADER_VALUE_MAX]; /* "{unixtime}.{pid}.{box}", set by set_vdm_id */
  gelf_context_t context;
} gelf_t;

int gelf_load_config(config_t *config, int check_mode);
void log_process_start(gelf_t *gelf);
void gelf_log(gelf_t *gelf, int severity, const char *buf, const char *full_message);
void log_delivery(gelf_t *gelf, delivery_log_t* d);
void log_exit(gelf_t *gelf, int code, bool success, int severity, const char *qms_message, const char *buf);
const char *quota_calc_source_name(int source);
void set_vdm_id(gelf_t *gelf);
int gelf_setup(gelf_t *gelf, char *reason_out, size_t reason_size);
int start_logging(gelf_t *gelf, char *reason_out, size_t reason_size);
int test_log_file(const char *path, char *reason_out, size_t reason_size);

#endif
