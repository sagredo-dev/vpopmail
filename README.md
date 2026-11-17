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

Checking a yescrypt password needs about 16 MiB of memory. `vchkpw` and `vpopmaild` often run
under a memory limit (`softlimit` in their run scripts); if it is too low for that, the login
is refused and `could not check the password (memory limit too low?)` is logged instead of a
password failure. `vchkpw` logs to syslog, `vpopmaild` to standard error.

When a user logs in through `vchkpw` or `vpopmaild` with a password whose hash uses an older
scheme, it is stored again in the current scheme, so hashes are upgraded as users log in
(`--disable-rehash-passwords` turns this off). Hashes are never replaced by an older scheme.
Making the new hash needs memory too (about 16 MiB for yescrypt, 64 MiB for Argon2id). When
it cannot be made, usually because the memory limit (`softlimit`) is too low, or cannot be
stored, the login still succeeds, the old hash stays, and `vchkpw` or `vpopmaild` logs
`password not rehashed` with the reason.
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
working, and `vchkpw` and `vpopmaild` upgrade them at login as above.

Keep in mind:
- Checking an Argon2id password needs 64 MiB of memory. `vchkpw` and `vpopmaild` often run
  under a memory limit (`softlimit` in the run scripts of qmail-smtpd, qmail-submission,
  qmail-pop3d and vpopmaild), which then needs to be about 100 MB or more. With less, the login
  is refused, and `not enough memory to check the password` is logged instead of a password
  failure. yescrypt needs about 16 MiB.
- Only builds with `--enable-argon2id-passwords` can check Argon2id hashes. Once users have
  them, building without the option again locks those users out until their password is
  reset.
- Programs that read `pw_passwd` themselves (scripts, PHP tools) see the `{ARGON2ID}` prefix
  and need to handle it.
- The LDAP module stores the hash as `{crypt}{ARGON2ID}$argon2id$...`; it checks passwords
  itself, but an LDAP server that checks binds against `userPassword` will not understand it.

## Upgrading

For the upgrading notes, please refer to [UPGRADE.md](doc/UPGRADE.md).

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
