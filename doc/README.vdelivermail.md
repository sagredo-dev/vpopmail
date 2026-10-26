# `vdelivermail`

`vdelivermail` is the key to the proper operation of your `vpopmail` installation.
When qmail attempts to deliver a message to a `vpopmail` domain the first thing
it does is look for delivery instructions in the following order:

 - if `valias` is enabled (`--enable-valias`) the SQL valiases are exetuted.

 - a `.qmail-user` file that matches the username (`.qmail-bob` is searched if the
   recipient is bob@domain.tld).

 - a `.qmail` file that matches the incoming address within the top level directory
   for the domain.

 - If no such _.qmail-*_ file is found, `qmail-local` executes the  _.qmail-default_
   file for the domain. This is the point where vpopmail takes over the the delivery
   process.  Vdelivermail searches the user database for the domain, and either
   delivers the message to one of its existing accounts, or looks to its second
   parameter for instructions on what to do with messages to accounts that do not exist.

For `vpopmail` to operate properly, the _.qmail-default_ file in the domain directory must
be setup properly.  There should only be one line in the file, and it must look like this:

```
   | /path/to/vdelivermail '' delivery-instruction

   | - The initial pipe tells qmail-local to execute a program.

   /path/to/vdelivermail - This is the program that must be executed.

   ''  This unused, empty parameter is required for historical reasons.
```

_delivery-instruction_ must be one of:

```
   someone@anotherexample.com   - an email address anywhere in the world.

   /path/to/some/Maildir        - a Maildir on the local server that the 
                                  vpopmail user has write access to.   

   delete                       - Delete all mail to non-existant users

   bounce-no-mailbox            - Bounce all mail to non-existant users
```

`bounce-no-mailbox` is no longer recommended, as it allows your mail server to be used
in Joe-Jobs. It now seems better to delete all mail to invalid addresses rather than
spamming the random senders used by spam-bots.

When creating a domain you can use one of the following:

```
   vadddomain -b someone@anotherexample.com example.com [password]

   vadddomain -b /path/to/some/Maildir example.com [password]

   vadddomain -b delete example.com [password]

   vadddomain -b bounce-no-mailbox example.com [password]
```

In summary... the _.qmail-default_ of every virtual domain MUST contain ONLY a single 
line that executes `vdelivermail`. The ONLY place you should EVER call `vdelivermail`
is from the _.qmail-default_ file of a `vpopmail` based virtual domain.  There are
four possible delivery options for non-existant mailboxes that must be the second
parameter to vdelivermail. The empty first parameter is required.

If you are not sure what you are doing writing _.qmail_ files, and mucking around
the internals of `vpopmail`, leave this file to the programs.
`Qmailadmin` is probably the easiest way to manage the _.qmail-default_ file once the
domain has been created.

Due to the requirement that Maildirs accessed by `vpopmail` must be owned by `vpopmail`
it is best to place all domains under `vpopmail`. While it is possible to continue
to have system users, and other styles of `qmail` virtual domains on a `vpopmail`
system, you really have to be a `qmail` guru to make it all work.

## Changes in version 5.7

Thanks to [rohan-bb69](https://github.com/rohan-bb69/vpopmail/) for the `vdelivermail` upgrade
that is introduced below.

**1** 
Build: `inih` (to read `vdelivermail.ini`) and `cJSON` (to build the JSON log records) are now required;
`configure` stops with an install hint if either is missing. `libcurl` (to parse the Date: header)
is optional.

**2** 
Before the first delivery: `vdelivermail` defers every delivery if `~vpopmail/etc/vdelivermail.ini`
is missing or invalid, or if the log file it names can't be opened (a missing directory isn't created).

**3** 
`vdelivermail` reads `~vpopmail/etc/vdefaultdelivery` instead of `qmail`'s `control/defaultdelivery`.
`make install` installs one containing `./Maildir/` if it's missing, and no longer writes
`control/defaultdelivery`. A `|...vdelivermail` line in it is deprecated and delivers to `./Maildir/`,
as v5.6 did.

**4** Now defers, where v5.6 bounced or delivered:

 - _maildirsize_ can't be rebuilt (v5.6 bounced it as over quota)
 - _vdefaultdelivery_ unreadable, or with a line over 299 characters (v5.6 fell back to ordinary delivery)
 - the new message file's name is already taken (v5.6 replaced the earlier file)
 - `vdelivermail` run as root

**5** Now bounces, where v5.6 delivered:

 - a sender address (RPLINE) containing a CR, or too long
 - a recipient address too long to handle (v5.6 truncated it)
 - a destination maildir with no `cur/` directory

**6** Now delivers, where v5.6 deferred:

 - a user-not-found instruction given as a _Maildir_ path (5.1)
 - a `.qmail` or `vdefaultdelivery` _Maildir_ line with a CRLF line ending (5.2)

**7** `Delivered-To:` is now always the dealiased envelope recipient. v5.6 wrote the alias 
domain on forwards, and the _Maildir_'s owner on some maildir deliveries. A new `X-Original-To:`
header keeps the original recipient when it differs.

**8** Quota: the database quota now applies on every route into an account's own _Maildir_,
so a mailbox that v5.6 left effectively unlimited (no _maildirsize_) or held to a stale _maildirsize_
is now held to its database quota. The quota-warning template now comes from the destination 
_Maildir_'s domain.

## Testing
To try a delivery without writing into a maildir, run it as the vpopmail user with `-d`, which writes the message to stdout instead:

```
sh EXT=user HOST=example.com RPLINE=$'Return-Path: <sender@example.net>\n' \
    ~vpopmail/bin/vdelivermail -d '' bounce-no-mailbox < test.eml
```

`-d` only diverts the final maildir write. Forwards and programs in valias rows or .qmail files still run for real.


## Configuration

The config file `~vpopmail/etc/vdelivermail.ini` holds the settings for `vdelivermail`. It must be present and valid. If not,
`vdelivermail` logs to stdout and defers all deliveries. It also parses the _vdefaultdelivery_ file at the beginning and
bails out in the same way if unsatisfactory. The `VPOPMAIL_VDELIVERMAIL_CONFIG` environment variable can name a different
config file, which is handy for testing.

Three settings in the `[main]` section of `vdelivermail.ini` can switch off things v5.6 always did. All default to on:

- `ensure_homedir_is_set_in_db`: if the user's homedir field in the database is blank, create the homedir and Maildir, and store the path
- `ensure_homedir_exists_on_disk`: if the homedir field is set but the directory is missing, recreate it with its Maildir
- `execute_dotqmail`: follow the .qmail file in the user's homedir, or in a homedir given as the user-not-found instruction

The `ensure_` settings are for installations where `Dovecot` does all the maildir writing, so `vdelivermail` shouldn't create
directories itself. `execute_dotqmail=0` reduces surprises on sites that expect all non-default deliveries to be defined by 
valias lines in the vpopmail db.


## Delivery instructions

**1** A user-not-found instruction given as a Maildir path never delivered in 5.6. The old README.vdelivermail and vadddomain's help both list
`/path/to/some/Maildir` as one, but v5.6's `usernotfound()` treated every argument starting with `/` as a home directory and appended `Maildir/`.
It then tried to deliver to `/path/to/some/Maildir/Maildir/`, which doesn't exist, and deferred with "can not open new email file" and "system
error". Only the home-directory form worked: the man page documents it and `vadddomain -e` writes it, but README.vdelivermail doesn't mentioned it.
Now both forms work. An existing directory is taken as a home directory if its path doesn't end in `/`, or it contains a `Maildir/` directory 
or a .qmail file. Anything else is taken as the Maildir itself, and must end in `/`.

**2** Reading the user's _.qmail_ (or `.qmail-ext/.qmail-default`) in `check_forward_deliver()`, compared with v5.6:

- The whole file is now read before any line is acted on. A file that can't be read, or that has a line longer than 299 characters, is logged as
an ERROR and treated as absent. With `--enable-qmail-ext`, the next file in the lookup order is then used (for bob-foo-bar: .qmail-foo-bar,
.qmail-foo-default, .qmail-default, .qmail); after that, or without that option, default delivery. v5.6 silently treated an unreadable file
as absent, and silently split any line over 499 characters into two separate instructions. (qmail-local defers on an unreadable .qmail, and
has no line length limit.)
- A trailing CR is stripped from each line, so CRLF files work. In v5.6 the CR stayed in the instruction: a Maildir line failed the trailing `/`
test and deferred as an mbox delivery, and a program line got a CR on its last argument. (qmail-local doesn't strip CR either.)
- A blank first line defers, like qmail-local's "first line of .qmail file is blank (`#4.2.1`)". Unlike qmail-local, a first line of only
spaces or tabs isn't treated as blank.

**3** `check_default_delivery()` - the vdefaultdelivery file:

- A vdefaultdelivery file that exists but can't be read, or has a line longer than 299 characters, now defers. v5.6 treated an unreadable
file as absent, falling back to ordinary delivery. It also silently split lines over 499 characters.

**4** An invalid forwarding address in a valias line or _.qmail_ file (too long, an empty local part or domain, or illegal characters) now
bounces, with the reason logged. v5.6 handed it to qmail-inject and reported the result as "system error calling qmail-inject".

**5** Valias changes:

**a.** A user record is looked up and passed to every line. v5.6 delivered every valias line with no user record: `deliver_mail(line, "")`.
Now `process_valias()` looks up the user the same way as `main()`: the full local part, then with QMAIL_EXT the base name. It does this
whichever row matched. A row keyed by an existing user therefore acts as that user's .qmail.

A wildcard row is not keyed by a user: when a bob-default row catches mail for bob-shopping@, the lines get a user record only if a user
named bob-shopping exists or, with QMAIL_EXT, a user named bob.

The user record changes how maildir lines are handled: a path within the user's own Maildir gets the user's database quota and flags, 
where v5.6 used maildirsize only.

**b.** New `:default` directive. It does what `main()` would have done without any valias rows:

- With a user record: the same steps as `checkuser()`. A locked account bounces. The homedir is checked or created (per configuration),
then the user's .qmail (if `execute_dotqmail` is on), then vdefaultdelivery, then `Maildir/`. After delivering, processing continues with
the next valias line. The user's own valias rows aren't consulted again, which avoids recursion.
- Without a user record: the domain's user-not-found instruction runs (address, maildir or command). `bounce-no-mailbox` and `delete` end
processing there, so later lines are skipped.

**c.** The DEFAULT environment variable is scoped to the lines of a wildcard valias line, that is, one where the "alias" field ends in 
"-default". qmail-local sets DEFAULT for commands it runs (see qmail-command(8)), and vdelivermail sets it again for -default valias rows.
v5.6 called `putenv()` once at the match, so every later action in the process saw the remainder. Now ordinary lines in a wildcard row see
the remainder (shopping for bob-shopping@ via bob-default), and qmail-local's original value (the whole local part, case kept) is put back
after each one. `:default` sees the original, as `main()` would have. Rows matched exactly or by base name never change DEFAULT.


## Logging

Each delivery is logged to `~vpopmail/log/vdelivermail.log`.

An example: one delivery, as logged with `format=pretty` (the default). Each run also logs a "start" event, and an "exit" event with the
result, exit code and message size; all of a run's events share its `vdm_id`.

```json
{
  "time": "2026-10-13T08:39:56+08:00",
  "event": "delivery",
  "severity": "info",
  "short_message": "Delivering to bob@example.com",
  "to": "bob@example.com",
  "from": "alice@example.net",
  "header_subject": "📈 Quarterly report",
  "header_message_id": "<20261013090000.1234@example.net>",
  "domain": "example.com",
  "user": "bob@example.com",
  "instruction": "./Maildir/",
  "source": "defaultdelivery",
  "method": "maildir",
  "success": 1,
  "maildir_path": "/home/vpopmail/domains/example.com/bob/Maildir",
  "maildir_owner": "bob@example.com",
  "maildir_quota_source": "db",
  "maildir_quota_allocated_bytes": 1048576,
  "maildir_initial_bytes": 6485,
  "maildir_quota_initial_bytes_source": "maildirsize_recalc",
  "maildir_quota_check_duration": 0.001,
  "maildir_not_enough_space": 0,
  "maildir_nearly_full": 0,
  "maildir_quota_warning_delivered": 0,
  "vdm_id": "1791851996.1188506.mail.example.com",
  "time_sent": "2026-10-13T07:00:00+08:00"
}
```

In the incoming message, the Subject header was RFC 2047-encoded as "=?UTF-8?B?8J+TiCBRdWFydGVybHkgcmVwb3J0?=" (7.3).

Logged header values are made safe in one pass, after decoding. While a field is read its bytes are kept exactly as they 
arrived (folded lines joined). Once it is complete, Subject, From, Sender, To and Cc are RFC 2047-decoded, and then every logged 
field is sanitised: valid UTF-8 is kept, so SMTPUTF8 (RFC 6532) headers log readably, while each invalid byte, control character 
(C0, DEL, C1) and bidi or invisible format character (e.g. U+202E, zero-width space) becomes U+FFFD, and a tab becomes a space. 
Replacing rather than deleting stops neighbouring text joining into something the sender never sent. Sanitising after decoding means
the decoder sees what the sender sent, and its output, which it copies through without checking, is still validated.

RFC 2047 encoded-word decoding for logged header fields. Took fmt_rfc2047.c from nmh, a command-line mail client (3-clause BSD 
license), to decode Subject line headers so that they are readable in the logs.

Logged header values such as Subject arrived as "=?UTF-8?B?8J+TiCBRdWFydGVybHkgcmVwb3J0?=" and are now decoded to text (7.1). 
Uses nmh's decoder, embedded in the tree in the same manner as `cdb/` and the Courier-derived maildirquota code.

- Decoded: subject, from, sender, to, cc.
- Only UTF-8 and US-ASCII encoded-words are decoded. Every other charset is logged exactly as it arrived, which loses nothing:
an encoded-word is losslessly decodable later by whatever reads the logs.
- No new library dependency. HAVE_ICONV is deliberately not defined, so no gconv module is ever loaded on a sender-supplied 
charset name and no AM_ICONV is needed. Reasons in `nmh/README.md`.

Added `format=pretty` and `format=gelf` for logging to a file. pretty is still valid JSON, but it's intended for humans and 
drops various GELF-specific fields. With `format=pretty`, grep can't easily pull out a whole log record, as each one spans several
lines. Many users may prefer `format=gelf` in conjunction with grep/tail etc, piped to jq. `format=gelf` could be consumed by filebeat.

Require libm to `round()` quota consumption calc durations. `libm` is pulled-in already for many other libraries used by `vdelivermail`.

