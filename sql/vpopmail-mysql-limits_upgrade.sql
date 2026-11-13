/*
  MySQL / MariaDB only, with --enable-mysql-limits. Run on an existing vpopmail
  database: perm_maillist holds three sets of permission bits (lists, list users,
  list moderators), values up to 511, which do not fit in TINYINT.
 */

ALTER TABLE `limits` MODIFY `perm_maillist` SMALLINT NOT NULL DEFAULT 0;
