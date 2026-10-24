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

**9** `valias`: every line now gets the user record, there's a new `:default` instruction, and
the DEFAULT environment variable is scoped to wildcard rows.

**10** Logging: each delivery is logged to `~vpopmail/log/vdelivermail.log`.
