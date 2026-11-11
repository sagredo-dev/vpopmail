# `vpopmail`

`Vpopmail` is a set of programs for creating and managing multiple virtual domains on a qmail server,
with full support for many POP/IMAP servers.

This is a fork of [brunonymous/vpopmail](https://github.com/brunonymous/vpopmail) from version 5.6.1 onwards, which already included my patches for `Vpopmail`. It also merges all the commit history with proper git attribution from [DerDakon/vpopmail](https://github.com/DerDakon/vpopmail)

Latest 5.7 version of `Vpopmail` requires `inih` (to read _vdelivermail.ini_). `libcurl` (to read the Date: header in the logs) is an optional dependence.

## Password hashing

New passwords are hashed with yescrypt (`$y$...`) when the system's `crypt()` supports it,
which is the case with libxcrypt (all current Linux distributions); otherwise configure falls
back to SHA512 (`$6$...`). `--disable-yescrypt-passwords` keeps SHA512.

Existing hashes keep working: passwords are checked with `crypt()`, which reads the scheme
from the stored hash, so a database with a mix of MD5, SHA512 and yescrypt hashes is fine and
no column needs to change (a yescrypt hash is 73 characters).

When a user logs in through `vchkpw` or `vpopmaild` with a password whose hash uses an older
scheme, it is stored again in the current scheme, so hashes are upgraded as users log in
(`--disable-rehash-passwords` turns this off). Hashes are never replaced by an older scheme.
Users whose logins never go through `vchkpw` or `vpopmaild` (for example IMAP/POP3 with
dovecot reading the SQL table directly) get the new scheme when they next change their
password.

Anything else that checks the hashes itself must support yescrypt. Dovecot's `CRYPT` and
`SHA512-CRYPT` schemes both hand the hash to the system's `crypt()`, which picks the algorithm
from the hash itself. So a dovecot SQL passdb with `passdb_default_password_scheme =
SHA512-CRYPT` keeps working unchanged with a mix of yescrypt, SHA512 and MD5 hashes (MD5 still
needs `auth_allow_weak_schemes = yes`, as before), provided dovecot runs on a system whose
`crypt()` supports yescrypt (libxcrypt). If dovecot, or any other program that checks these
hashes, runs on a system without it, configure vpopmail with `--disable-yescrypt-passwords`.

### Argon2id (optional)

`--enable-argon2id-passwords` hashes new passwords with Argon2id instead, using libsodium
(`apt install libsodium-dev`), with libsodium's interactive limits (64 MiB of memory per
hash). The hashes are stored as `{ARGON2ID}$argon2id$v=19$...` (107 characters): dovecot
uses the `{ARGON2ID}` prefix to pick the scheme, whatever `passdb_default_password_scheme`
says, so a dovecot SQL passdb needs no configuration change, but dovecot must be built with
libsodium (`doveadm pw -l` lists `ARGON2ID`; the Debian packages are). Old hashes keep
working, and `vchkpw` upgrades them at login as above.

Keep in mind:
- Checking an Argon2id password needs 64 MiB of memory. Programs that check passwords under
  a memory limit (`vchkpw` started by qmail-smtpd or qmail-pop3d, `vpopmaild`, often run
  under `softlimit`) need a limit of about 100 MB or more; with less, the check fails and the
  login is refused as if the password were wrong. yescrypt needs about 16 MiB.
- Only builds with `--enable-argon2id-passwords` can check Argon2id hashes. Once users have
  them, building without the option again locks those users out until their password is
  reset.
- Programs that read `pw_passwd` themselves (scripts, PHP tools) see the `{ARGON2ID}` prefix
  and need to handle it.
- The LDAP module stores the hash as `{crypt}{ARGON2ID}$argon2id$...`; it checks passwords
  itself, but an LDAP server that checks binds against `userPassword` will not understand it.

## Upgrading from version 5.4.33

When upgrading from version 5.4.33 to version 5.6.x, if you have the accounts on SQL, you should
enlarge the `vpopmail.pw_passwd` column size, as the default password encryption is SHA512, which is
longer than the old MD5; you can disable SHA512 pwd with `--disable-sha512-passwords` at configure time.
The default dimension for the `vpopmail.pw_passwd` column is now 128.  
Here is the SQL query to upgrade the `vpopmail` table:

``` sql
ALTER TABLE `vpopmail` CHANGE `pw_passwd` `pw_passwd` VARCHAR(128) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
```

### Changes for PostgreSQL only

You have to widen the columns that hold IP addresses from varchar(18) to varchar(39), so that IPv6
addresses fit (as already done for MySQL). Only run the statements for the tables that exist in your database:

    relay         --enable-roaming-users
    lastauth      --enable-auth-logging
    ip_alias_map  --enable-ip-alias-domains


``` sql
ALTER TABLE relay ALTER COLUMN ip_addr TYPE varchar(39);
ALTER TABLE lastauth ALTER COLUMN remote_ip TYPE varchar(39);
ALTER TABLE ip_alias_map ALTER COLUMN ip_addr TYPE varchar(39);
```

## Upgrading from version 5.6.3

Several other non breaking changes have been made to the `MySQL` tables' layout.  
Here is how you can quickly alter the tables (inlcluded the change mentioned above):

``` sql
/* vpopmail */
ALTER TABLE `vpopmail` CHANGE `pw_name` `pw_name` VARCHAR(64) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 
ALTER TABLE `vpopmail` CHANGE `pw_domain` `pw_domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 
ALTER TABLE `vpopmail` CHANGE `pw_passwd` `pw_passwd` VARCHAR(128) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
ALTER TABLE `vpopmail` CHANGE `pw_gecos` `pw_gecos` VARCHAR(64) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
ALTER TABLE `vpopmail` CHANGE `pw_dir` `pw_dir` VARCHAR(160) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
ALTER TABLE `vpopmail` CHANGE `pw_shell` `pw_shell` VARCHAR(20) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL; 

/* vlog */
ALTER TABLE `vlog` CHANGE `user` `user` VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL; 
ALTER TABLE `vlog` CHANGE `passwd` `passwd` VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
ALTER TABLE `vlog` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL; 
ALTER TABLE `vlog` CHANGE `remoteip` `remoteip` VARCHAR(39) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL; 
ALTER TABLE `vlog` CHANGE `error` `error` TINYINT(1) NULL DEFAULT NULL;
ALTER TABLE `vlog` CHANGE `timestamp` `timestamp` INT NOT NULL DEFAULT '0'; 

/* lastauth */
ALTER TABLE `lastauth` CHANGE `user` `user` VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 
ALTER TABLE `lastauth` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 
ALTER TABLE `lastauth` CHANGE `remote_ip` `remote_ip` VARCHAR(39) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL;
ALTER TABLE `lastauth` CHANGE `timestamp` `timestamp` INT NOT NULL DEFAULT '0'; 

/* limits */
ALTER TABLE `limits` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 

/* alias */
ALTER TABLE `valias` CHANGE `alias` `alias` VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL;
ALTER TABLE `valias` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL;

/* dir_control */
ALTER TABLE `dir_control` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL;

/* aliasdomains */
ALTER TABLE `aliasdomains` CHANGE `alias` `alias` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL;
ALTER TABLE `aliasdomains` CHANGE `domain` `domain` VARCHAR(96) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL; 
```

## Usage for `s/qmail` users

The location of the users' cdb file in [`s/qmail`](https://www.fehcom.de/sqmail/sqmail.html) is `assign.cdb`.
Therefore `s/qmail` users have to configure `vpopmail` by adding the following to the configure command:

```
--enable-qmail-cdb-name=assign.cdb
```

`s/qmail` users can use the [`vrcptcheck`](https://github.com/sagredo-dev/vpopmail/blob/main/vrcptcheck.c) program to
perform the recipient check, provided that `qmail-smtpd` is run as the `vpopmail` user.
Just call the program within `control/recipients` as follows:

```
echo "*|/path/to/vpopmail/bin/vrcptcheck" >> /var/qmail/control/recipients
```

## More info and support

To find more info and ask for support post a comment in [my blog](https://notes.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html).
