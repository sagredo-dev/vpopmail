/*
  SQL query to be run only if the tables to be updated are already present in the vpopmail database
  and if vpopmail has been configured in the following way:
    --enable-sql-aliasdomains
    --enable-auth-logging
    --enable-vlimits
    --enable-valias
    --enable-auth-logging
    --enable-sql-logging
    --enable-many-domains (default, all domains in the same vpopmail table)
 */


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
