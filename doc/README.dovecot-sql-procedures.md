# dovecot-sql-procedures patch

by Roberto Puzzanghera  
More info [here](https://notes.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html)

If you want to use the dovecot's sql auth driver with one table for each domain (--disable-many-domains) you have
to heavily customize your password_query and user_query.  
With this patch vpopmail installs the sql procedures and functions in the database when you create a new domain.
The procedures can be called by dovecot to perform the auth.  
The sql stuff supports aliasdomains and mysql limits and will be loaded from ~/vpopmail/etc/disable-many-domains_procedures.sql.
You can customize the sql procedure editing this file.  
Be aware that the aliasdomains support requires that you patched your vpopmail accordingly with my
sql-aliasdomains patch.

Read the reference above for more info.

## Settings

This patch must be installed over the "sql-aliasdomains" patch.

An autoreconf is needed as I modified the original configure.in and Makefile.am files.

Configure as follows:

```
autoreconf -f -i
./configure --disable-many-domains --enable-sql-aliasdomains --enable-mysql-bin=PATH
```

## dovecot configuration

### auth-sql.conf.ext

```
passdb {
  driver = sql
  args = /usr/local/dovecot/etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = prefetch
}
```

This is for LDA.

```
userdb {
  driver = sql
  args = /usr/local/dovecot/etc/dovecot/dovecot-sql.conf.ext
}
```
### dovecot-sql.conf.ext

```
password_query = CALL dovecot_password_query_disable_many_domains('%n','%d','127.0.0.1','%r','%a')
user_query = CALL dovecot_user_query_disable_many_domains('%n','%d')
```
