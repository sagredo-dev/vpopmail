# dovecot-sql-procedures patch

by Roberto Puzzanghera  
More info [here](https://www.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html)

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

### dovecot-sql.conf.ext

```
passdb sql {
 # passdb query to retrieve the password

 # Thanks to Pablo Murillo for sharing his sql example
 query = CALL dovecot_password_query_disable_many_domains('%{user | username}','%{user | domain}','127.0.0.1','%{remote_ip}','%{local_port}')
} 

userdb prefetch { 
 driver = prefetch 
} 

# This is needed for LDA and for the iteration feature. They both need a userdb sql query. 
# The order of the declared drivers is important. Leave this at the end, otherwise 
# it will be used also for the login instead of the prefetch, which is faster. 
userdb sql { 
 userdb_sql_query = CALL dovecot_user_query_disable_many_domains('%{user | username}','%{user | domain}')
}
```
