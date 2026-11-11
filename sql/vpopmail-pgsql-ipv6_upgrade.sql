/*
  PostgreSQL only. Run on an existing vpopmail database to widen the columns
  that hold IP addresses from varchar(18) to varchar(39), so that IPv6
  addresses fit (as already done for MySQL). Only run the statements for the
  tables that exist in your database:
    relay         --enable-roaming-users
    lastauth      --enable-auth-logging
    ip_alias_map  --enable-ip-alias-domains
 */

ALTER TABLE relay ALTER COLUMN ip_addr TYPE varchar(39);
ALTER TABLE lastauth ALTER COLUMN remote_ip TYPE varchar(39);
ALTER TABLE ip_alias_map ALTER COLUMN ip_addr TYPE varchar(39);
