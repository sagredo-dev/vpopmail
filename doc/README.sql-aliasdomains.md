# sql-aliasdomains patch

by Roberto Puzzanghera  
More info [here](https://www.sagredo.eu/en/qmail-notes-185/dovecot-vpopmail-auth-driver-removal-241.html)

This patch makes vpopmail store domain aliases to MySQL. This gets dovecot's sql auth driver aware of domain aliases, provided that you modify the sql query accordingly.

## Settings

* An `autoreconf` is needed as I modified the original configure.in and Makefile.am files

```
  autoreconf -f -i
  ./configure \
	--enable-auth-module=mysql \
	--enable-sql-aliasdomains (default)
```

* Adjust your dovecot-sql.conf.ext in order to auth both real and alias domains (more info [here](https://www.sagredo.eu/en/qmail-notes-185/installing-dovecot-and-sieve-on-a-vpopmail-qmail-server-28.html#sql):

```
password_query = \
        SELECT \
                CONCAT(vpopmail.pw_name, '@', vpopmail.pw_domain) AS user, \
                vpopmail.pw_passwd AS password, \
                vpopmail.pw_dir AS userdb_home, \
                89 AS userdb_uid, \
                89 AS userdb_gid, \
                CONCAT('*:bytes=', REPLACE(SUBSTRING_INDEX(vpopmail.pw_shell, 'S', 1), 'NOQUOTA', '0')) AS userdb_quota_rule \
        FROM `vpopmail` \
                LEFT JOIN aliasdomains ON aliasdomains.alias='%d' \
        WHERE \
                vpopmail.pw_name='%n' \
                AND \
                (vpopmail.pw_domain='%d' OR vpopmail.pw_domain=aliasdomains.domain) \
                AND \
                ('%a'!='995' OR !(vpopmail.pw_gid & 2)) \
                AND \
                ('%r'!='[WEBMAIL-IP]' OR !(vpopmail.pw_gid & 4)) \
                AND \
                ('%r'='WEBMAIL-IP' OR '%a'!='993' OR !(vpopmail.pw_gid & 8))

user_query = \
        SELECT \
                vpopmail.pw_dir AS home, \
                89 AS uid, \
                89 AS gid \
        FROM vpopmail \
        WHERE \
                vpopmail.pw_name='%n' \
                AND \
                vpopmail.pw_domain='%d'

```

* Create/delete aliasdomains in the usual way with `vaddaliasdomain/vdeldomain`

* If you already have aliasdomains, you have to populate the dbtable. You can use my "vsavealiasdomains" program to save all your domain aliases to MySQL.  
  Type `vsavealiasadomains -A` to save all your domain aliases to MySQL.  
  Type `vsavealiasadomains -h` for more options.
