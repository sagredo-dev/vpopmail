Vpopmail is a set of programs for creating and managing
multiple virtual domains on a qmail server originally developed by [Inter7](http://www.inter7.com/vpopmail-virtualized-email/).

It is geared toward ease of use for system administrators as well 
as security and efficency. With the associated command line programs,
system administrators never need touch any of the underlying qmail files 
and processes. All details are automatically handled. 

Features include  
  * Support for 1 to 23 million virtual email domains using a 
    "grow as it goes" balenced directory tree. 
  * Support for 1 to 23 million email users per domain using the
     same balenced tree structure. 
  * Automates all qmail configurations into handy and scriptable
    command line programs and documented API library calls. 
  * Automates Unix user/group/other permissioning of directories
    and files. 
  * Supports authenticated relay control of your qmail smtp server. 
  * Virtual email file/directories can be assigned to any user/group
    or do the default vpopmail/vchkpw 89/89. 
  * Does not require email user accounts in /etc/passwd 
  * Supports name or IP based virtual domains 
  * Optionally automates support for: 
      * Storing clear text passwords to help tech support workers 
      * Record last authentication and automates deletion of
        stale accounts. 
      * Storing alias/forwards in mysql or oracle 
  * Configurable logging based on real world admin's comments
    and requirements. 
  * Support for MySQL, Oracle, PostgreSQL, /etc/passwd, /etc/shadow,
     LDAP, Sybase, SQLite and default cdb authentication storage. 
  * Delivers directly to Maildir for use with qmail-pop3d,
    .qmail files or any other Maildir program. 
  * No need to have hundreds of .qmail files for virtual domains.
    Each domain gets it's own directory under vpopmail user with a
    separate password file for each domain. 
  * Documented C library for all vpopmail features and transactions. 

By default, vpopmail stores all the account configuration and settings
in CDB files. CDB is a fast, reliable & simple database package that was
written by Dan Bernstein (the author of qmail). CDB is a good choice
for small vpopmail sites, but if you are running a larger server,
there are other authentication modules available that can help increase
performance or improve managability.

For help concerning vpopmail's features look at the documentation in the *doc* directory.

## Qmail and Virtual domains

Qmail has an idea of email domains that are "local" and "virtual". Local
domains are ones which primarily match against /etc/passwd. Virtual domains
match against domains listed in the qmail control file "virtualdomains".
Vpopmail makes use of the qmail users/assign file and virtualdomains file.
The users/assign file gets compiled into a users/cdb file. It is a hashed
database to speed searches for patterns. If a pattern is matched then qmail
delivers the email to the directory defined in the file using the uid and
gid which as also defined. Vpopmail makes use of this method to have qmail
deliver all virtual domain email as the single uid/gid vpopmail/vchkpw.
It also uses it to direct delivery to a vpopmail/domains/<virtualdomain>
directory.

Once qmail-local gets the information from the users/assign file it performs
standard .qmail file processing in the directory. Normal .qmail-<user> 
files can be used for forwarding, aliases or invoking programs such as ezmlm.
If no matches are found qmail-local looks for a .qmail-default file. This is
the last stage in qmail-locals delivery mechansim. Vpopmail uses this file 
to invoke the vdelivermail program. This program takes two parameters, the 
first is not used (it is there for backward compatibility). The second 
parameter is the default delivery if a virtual domain user can not be found. 
Basically, it can be a directory to deliver the email to, an email address to
forward the email to or the string "bounce-no-mailbox" to bounce the mail 
back to the sender.

Once vdelivermail is started up, it uses the core vpopmail api calls to 
check for a virtual domain user. If the user exists, the email is delivered 
into their directory. If vpopmail was configured for hard quotas (default 
is yes with 50Meg quota), then the size of the users current email files 
in their Maildir/new and Maildir/cur directories are counted. If the user 
is over quota the email is bounced back to the user with a bounce message 
that can be customized. If the message is 1Kbytes or smaller the email 
will always be delivered. This is so system administration programs can 
always get a message through to the user. 

## Directory structure

Overall vpopmail directory structure
Vpopmail gets it's own home directory. Under this directory there are 
the following:

  bin - contains all the binaries  
  lib - contains the libvpopmail.a file  
  include - contains the C header files  
  users - for backward compatibility for people who mix /etc/passwd users 
  with vpopmail users in one domain  
  domains - where all the virtual domains are kept.

## Virtual domain user directory structure

Vpopmail uses an adaptive directory structure based on a state file 
".dir-control" which is automatically managed by the core vpopmail api 
functions "vadduser" and "vdeluser". For sites with 100 users or less, 
all user directories are stored in the virtual domain directory. For 
sites that go above 100 users the adaptive directory structure goes into 
effect. The basic idea is to break up the user Maildir directories across 
multple directories and sub directories so that there are never more than 
100 user directories in a single directory.

The default directory setup allows for 62 directories in 3 levels and 
100 user directories per directory. The total number of user directories 
is equal to 100 + (62 * 100) + (62 * 62 * 100) + (62 * 62 * 62 * 100) = over 
24 million directories. This should be more than sufficent for any site 
and probably goes beyond the technology of directory structures. 

If you are going to be storing large numbers of user directories, make
sure you set your file system to have a higher than normal percentage 
of inodes. 

Vpopmail will automatically create these directories and sub directories 
as needed and populate each directory with up to 100 user accounts. As 
soon as a directory reaches 100 users it will create the next directory 
or sub directory and store the new users directory there. 

Look in the source code release directory contrib/ for a contributed 
directory reorganization program

## Converting current user accounts

The vconvert program can convert email accounts from one format into
another format. Conversion can be between /etc/passwd, vpasswd files,
mysql (small version) and mysql (large version).

Most current vpopmail users would probably be interested in how to
convert current domains into mysql domains. To make it simple to convert
an entire machine to mysql, use the following command: vconvert -c -s
This will go through all the domains in ~vpopmail/domains directory
and read each vpasswd file and load the contents into the
vpopmail.vpopmail mysql table. The vpasswd file is left untouched
for safety. Vconvert can also be run against one or more domains at a
time. This is done by running the command as so:
vconvert \c \s domain1 domain2 ...

To convert all users (except root and system accounts) into a mysql
domain run the following command: vconvert -e -s domain. This reads
all /etc/passwd accounts and creates mysql entries using their
passwords. The passwords can be in either /etc/passwd or /etc/shadow.
These passwords should work under vchkpw authentication program.

## Security and pop server under tcpserver

If all of your pop email accounts are under virtual domains, you can
increase the security of your pop server by running it under the uid
and gid of vpopmail/vchkpw using the tcpserver -u and -g options.

## Sorting qmail control files

vpopmail now sorts the qmail control files.  When adding a record vpopmail
uses an insertion sort to keep entries in order.  As it is doing this
sort, it verifies the order of all records in the file.  If if finds entries
that are out of order, it will sort the entire file by loading it into 
memory and using qsort.

The files that are sorted:  rcpthosts, morercpthosts, virtualdomains,
users/alias.  I don't believe there will be any problem having these 
files sorted, since they work in random order already.  It is much 
more convienent searching for a domain with the files in order, and 
programs like vdominfo and vpopmaild will report domain names in order.

At first glance, the sort order may seem bizarre, but once you work with
it, it should become natural.  Here is a small example from my test server:

developersdesk.com  
admin.developersdesk.com  
mail.developersdesk.com  
test.developersdesk.com  
developersdesk.net  
developersdesk.org  
mvas.com  
mvas.net  
mvas.org  
test.com

They are actually sorted as if they were written like this:

developersdesk.com.mail

I bet for most people that tends to group customers together.  A special
sort may be apropriate for domains that end in a country code.  If someone
has any ideas, post it on the SourceFORGE vpopmail-devel mailing list.

## More info and support

To find more info and ask for support post a comment [in my blog](https://www.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html). Pull requests are welcome in this github space.
