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
 */
typedef struct {
  int enabled;                   /* default 0 */
  const char* path;              /* default VPOPMAILDIR/log/vdelivermail.log; a relative
                                  * value in the ini is anchored to VPOPMAILDIR too */
  int min_severity;              /* default LOG_INFO (6) */
  int format;                    /* GELF_FORMAT_*; default PRETTY */
} file_target_t;

typedef struct {
  char log_source_hostname[256];    /* defaults to gethostname() */
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

/*
Also needed in the outcome log: n.b. this does not describe an individual delivery

INVOCATION LOG - entrance. Minimal, because the delivery attempt logs have more. no header_date. gelf timestamp is enough
event - "invocation" / start
vdm_id
domain
to
from
header-subject - maybe not, then we can emit before reading stdin
don't do user


EXIT LOG

_event - "exit"
timestamp - unix epoch time the log was emitted
time - human-readable time the log was emitted, in local timezone.
time_sent - unix epoch time from the Date: header in the message. When the message was sent.
time_sent_human - human-readable version of <time_sent>, in local timezone.
header_date - the unparsed Date: header string, only emitted when we don't have the library available to compute <time_sent>. Could be in multiple formats, in any timezone.
time_queued - unix epoch time for when the message was received by qmail-queue. Stable across defers and retries.
time_queued_human - human-readable version of <time_queued>, in local timezone.
vdm_id - {unixtime}.{pid}.{box} , with the box configurable as [main] log_source_hostname, defaulting to hostname. The time is our process start time.
app - vdelivermail
success - ? 0 for bounce or defer. ? Are there any EXIT_OK cases (e.g. empty stdin) that are actually failures?
code - like l4j code, numeric code, log4j style. useful for say HTTP etc. i.e. 111,100
shortmess - like l4j message, the message passed to vexiterr. Often user-facing, so can't contain the full valias instruction.
  Is this the same as bounce content? Better truncate this. Yes. Or is that longmess. We don't have access to the full bounce content (subject line?) anyway.
  Do we need something to log which valias line failed, or can we make that clear in the content of the vexiterr() message.
longmess - like l4j data. Delivered-To and/or Received lines when is_looping is 1?
result - OK, BOUNCE, DEFER. aka exit_code. probably better than numeric code. what about special exit code 99. need better name.
    Kind of return_code_to_qmail_send.
from - envelope sender
to - envelope recipient, reconstructed from env variables. document what happens with EXT stuff
  Also in the Original-To header if we do final delivery to Maildir. Could be an alias domain after the @ sign.

user - user@domain: only blank for usernotfound, or a rare valias row with no corresponding vpopmail row. domain part is dealiased.
  Always ends up in Delivered-To header. aka mailbox. omit when unknown. omitted implies usernotfound. Don't include until after vauth_getpw
domain - probably useful for searching in graylog. Means dealised domain, taken from user

WONT [put in DELIVERY log] quota_allocated_bytes - -1 means NOQUOTA (unlimited), 1 means no quota allocated (sort of), 0 (under vpopmail 5.4) meant no quota allocate
        Omit means not known. -1 is not the greatest, but I don't mind it. It disrupts queries for people with low quota allocation.
        perhaps search will just have to exclude the -1 case

qmail_send_log_message - the string sent to stdout for the benefit of qmail-send's own log stream. Maybe qmailmess

NOT HERE quota_warning_delivered - i.e. the additional message to the recipient. I'll probably disable, seeing as I'm using LMTP. different to over quota msg
size_bytes - 0 means not populated yet. Don't try and use this to detect an empty stdin. that's too obscure to devote a special value for.
size_known - 1 if size_bytes has been populated.
is_looping - check in main() and in maildir path i think
valias_count - means non-comment lines. See normal_delivery
valias_completed - how many non-comment lines completed without a failure
valias_instructions : \n delimited. Perhaps not warranted, if the user is willing to just examine the "delivery" events. Keep all comments.
    Worthwhile because it includes lines that never got a delivery event because you bounced or deferred early.
WONT normal_delivery_enabled - 
    To be 1, 
        the user must be known, and the there must either be no valias lines at all,
    or at least one valias line that delivers into the user's own Maildir inbox.
    Or there needs to be at least one :default line 
    Or there needs to be a .qmail line that delivers into the user's own Maildir inbox.
    Or there needs to be a defaultdelivery file that delivers into the user's own Maildir inbox.
    This is exhausting. Simpler:
    valias_normal_delivery_enabled - as above but ignore .qmail, defaultdelivery etc.
    0 when there's at least 1 valias line, but they're all comments.
    This is too site-specific. The inverse is easier to track: valias_discard_all
WONT dotqmail_instructions
WONT dotqmail_count
WONT dotqmail_completed

WONT defaultdelivery_instructions - the admin can look it up elsewhere    

WONT partial - 1 if some deliveries occurred, but we ended up with BOUNCE/DEFER. too much. 

how_many_qmail_inject called ? successful_forwards_count

catchall - usernotfound occurred, attempted catchall delivery instruction. Not needed in the DELIVERY logs 
  because the "source" field will say "catchall" for each of those. This flag helps admins find when the catchall path was attempted.
  Note that usernotfound is not set by the catchall pathway.
user_not_found - 1 if not found. Can also occur for valias-without-user case, but only if :default used.
    The `user` field will be absent. Not set to 1 by the catchall pathway. Without that exception, you could
    have misleading exit logs where usernotfound=1, but the actual error was something else.
bounced - 1 or 0 . ?always the same as code==EXIT_BOUNCE ?
    presumably we still set this even when SENDER is <>

also various mail headers:
header_subject - valuable because the exit log hasn't appeared yet and pairing with the start log requires tracing the vdm_id. Empty string when absent from message headers.
the tracking header, under its own derived field name


DELIVERY LOG, i.e. log of the attempt to execute a delivery instruction. it passes the message someplace. It's interpreted/executed by the interpreter.
    Some deliveries are not from user-configured instrutions: quotawarnings. Bounces are not considered deliveries.
    We log failed deliveries, even though we have the exit log? This allows us to log the exact command
    and avoid filling the exit log with method-specific informtaion.

event - "delivery" 
app - vdelivermail
instruction - e.g. "|autoresponder". Omitted for the most straightforward case, with no defaultdelivery file.
 Include prefix character. "&" added for forwards.
    omit for quotawarning. 
source - where the instruction came from: valias, .qmail, catchall, defaultdelivery. 
    Omit for the most straightforward path. Omit for quotawarning.
method - man page calls this "type" of instruction. program, forward, maildir  https://manpages.debian.org/buster/qmail/dot-qmail.5.en.html . 
    But we never log directives or comments.
    Q. do we omit for the most straightforward path? No, we use maildir.
success - It is worth recording unsuccessful. We don't want to clutter the exit log with, say, quota info.
    Still records success even if a quota warning can't be delivered.
from - same defn as in exit log
to - same defn as in exit log
<the tracking header> - under its own derived field name, starting with header_
timestamp - from header date
header_subject - valuable because the exit log hasn't appeared yet and pairing with the start log requires tracing the vdm_id. Empty string when absent from message headers.
user - as per exit log. Don't emit user if it's a valias with no corresponding vpopmail user.
domain - as per exit log.
vdm_id - used for correlating delivery attempts to each invocation of vdelivermail. Using the identical field name as for the exit event, because of the way graylog queries work.
code - exit code from qmail-inject or from the pipe program. Omit for maildir deliveries.

    MAILDIR DELIVERIES ONLY:
    maildir_path - absolute path, unlike instruction
    maildir_owner - name@domain of the account the maildir is confirmed to belong to. Omitted when unknown.
    maildir_quota_source - "db" or "maildirsize"
    maildir_quota_allocated_bytes - -1 means NOQUOTA.
    maildir_initial_bytes - quota consumption before we attempt delivery. Only populated when a quota
        is actually enforced (see manage_deliver_to_maildir's MAILDROP/NOQUOTA gating) -- 0 otherwise.
        e.g. Not set for the delivery of the quotawarn message.
    maildir_quota_initial_bytes_source - how maildir_initial_bytes was obtained: "daemon", "maildirsize_cached",
        "maildirsize_recalc" (the file was stale/missing and rebuilt from a full disk walk), or omitted
        if unknown.
    maildir_quota_check_duration - wall-clock time (floating-point seconds) spent obtaining maildir_initial_bytes. truncated/rounded to milliseconds
    maildir_not_enough_space - 1 if the message was not delivered, as doing so would exceed the quota.
    maildir_nearly_full - 1, if the maildir is above 90% *after* the message was delivered.
        This field appears within the delivery log of the primary delivery. 
        The delivery log of the warning message itself will not show this field.
        Omitted when the delivery failed, since it is only evaluated after a successful one.
    maildir_quota_warning_delivered - best here, refers to the warning message delivered to the recipient mailbox.
        Global template typicallyin /var/vpopmail/domains/.quotawarn.msg. Can be per-domain templates.
        A single process-run could trigger multiple warnings, but no more than one per delivery
        Sent for three possible reasons: 
            1. not enough space in user Maildir
            2. successful delivery occurred and maildir is now 90% or more full (see maildirquota.h, even in vpopmail 5.4)
            3. domain-overquota
        It's not delivered more than once a day, regardless of the reason.
        maildirquota.h had it set to 90%, even in vpopmail 5.4.      
    maildir_file_size_bytes - size of the file in the maildir after the message file was successfully 
        generated (within the maildir's tmp/) on disk.
        It's what goes into maildirsize's consumption log, when all goes well.
        Reported even when the file is then discarded instead of being filed, which SpamAssassin
        might do. Omitted whenever no complete file was produced, such as a write that
        failed part-way or a failed close. 
        Extra headers make it bigger than the incoming message. See size_bytes in the exit log.
        Special deliveries (e.g. quota warning) have a size unrelated to the incoming message's size.

    PROGRAM DELIVERIES ONLY:
    WONT [LOW PRI] longmess - stdout and stderr? that could be the whole bounce message. check how autoresponder works. might be difficult to collect sub-process stdout
    code - their exit code
    signal - signal received by child process
    WONT [write] pid - process id of the child process, not in the delivery log.



log_delivery("valias",instruction,SUCCESS)
log_maildir_delivery("valias",instruction,SUCCESS,maildir_quota_source,maildir_quota_allocated_bytes,maildir_quota_consumed_afterwards? or before?)

*/

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
 * gelf_log. sock is -1 until the first successful send. headers start empty;
 * typically filled by vdelivermail.c's extract_headers().
 */
typedef struct {
  config_t config;
  int log_fd;                    /* [file_log] target; -1 until opened by gelf_setup */
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

#endif
