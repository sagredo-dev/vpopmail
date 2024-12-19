# `vpopmail`

Vpopmail is a set of programs for creating and managing multiple virtual domains on a qmail server,
with full support for many POP/IMAP servers

## Upgrading from version 5.4.33

When upgrading from version 5.4.33 to version 5.6.x, if you have the accounts on SQL, you should
enlarge the `vpopmail.pw_passwd` column size, as the default password encryption is SHA512, which is
longer than the old MD5; you can disable SHA512 pwd with `--disable-sha512-passwords` at configure time.
The default dimension for the `vpopmail.pw_passwd` column is now 128.  
Here is the SQL query to upgrade the `vpopmail` table:

``` sql
ALTER TABLE `vpopmail` CHANGE `pw_passwd` `pw_passwd` VARCHAR(128) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL;
```

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

## More info and support

To find more info and ask for support post a comment in [my blog](https://notes.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html).
