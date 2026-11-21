# `vpopmail`

`Vpopmail` is a set of programs for creating and managing multiple virtual domains on a qmail server,
with full support for many POP/IMAP servers.

This is a fork of [brunonymous/vpopmail](https://github.com/brunonymous/vpopmail) from version 5.6.1 onwards, which already included my patches for `Vpopmail`. It also merges all the commit history with proper git attribution from [DerDakon/vpopmail](https://github.com/DerDakon/vpopmail)

Latest 5.7 version of `Vpopmail` requires `inih` (to read _vdelivermail.ini_). `libcurl` (to read the Date: header in the logs) is an optional dependency.

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
