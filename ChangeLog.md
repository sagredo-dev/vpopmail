# ChangeLog

Numbers in square brackets ([]) are tracker items on SourceForge with patch
or info related to the entry. <http://sourceforge.net/projects/vpopmail/>

5.6.8 - Released Mar 29, 2025
  - defaultdelivery feature (--enable-defaultdelivery) changes:
    * vdelivermail is installed by default in .qmail-default of newly created domains
      with option 'delete' as in the previous version.
    * if no user's valiases and no .qmail are found, then the message is sent
      to the control/defaultdelivery file, so that dovecot-lda (or whatelse) can
      store the mail into inbox and execute the sieve rules.
    * if vdelivermail is found in control/defaultdelivery, then it is ignored to avoid
      loops. The delivery remains in charge to vdelivermail.
    * v. 5.6.8 is backward compatible. The users having .qmail from previous versions
      of the defauldelivery feature are not affected by this change.

5.6.7 - Released Mar 23, 2025
  - Bug fix in vpopmaild.c: Crypted[64] enlarged to Crypted[128] to make room for SHA-512 passwords.
    This restores the usability of the RoundCube's 'password' plugin.
  - Fixed quota calculation in sql procedures for dovecot (tx Hakan Cakiroglu)
  - Minor changes to the usage function of vmakedotqmail.c

5.6.6 - Released Feb 15, 2025
  - bug fix: pwstr.h was not installed by Makefile (tx Bai Borko)

5.6.5 - Released Feb 9, 2025
  - added pwd strength check also for vadduser.c
  - removed -std=c99 -D_XOPEN_SOURCE=500 arguments from CFLAGS in configure.ac to make clang happy
  - several changes to compile on FreeBSD clang v. 18.1.6

5.6.4 - Released Dec 19, 2024
  - Added configurable password strength enforcement (Matt Brookings' 5.5.0-dev version).
  - Dropped min pwd length feature.
  - vmysql.h: tables' layout changed in order to have VARCHAR instead of CHAR.
    Fields containing ip addresses enlarged to VARCHAR(39), to create room for ipv6.
    Unix timestamps definition changed from BIGINT(20) to INT(11).

5.6.3 - Released Oct 19, 2024 (Roberto Puzzanghera)
  - bug fixed: passwords with length > 8 were denied if sha-512 was disabled

5.6.2 - Released Oct 14, 2024 (Roberto Puzzanghera)
  - fixed a configure break where a trivial C test program exits on error with gcc-14.1 due to missing headers
  - vusaged/domain.c: fixed -Wimplicit-function-declaration compilation warning
  - vusaged/configure: autoconf 2.71 compat
  - vmysql.h: dropped the multicolumn PRIMARY KEY in valias table to allow multiple forwards for a given alias.
    In case one already has the valias table defined, this is the sql query for the upgrade:
    ALTER TABLE `vpopmail`.`valias` DROP PRIMARY KEY, ADD INDEX (`alias`, `domain`, `valias_type`) USING BTREE;
    ALTER TABLE `vpopmail`.`valias` ADD `id` INT NOT NULL AUTO_INCREMENT FIRST, ADD PRIMARY KEY (`id`);

5.6.1
  - vmysql.c: allow the insertion of a second valias row with the same alias/domain
    when vpopmail is configured with --enable-defaultdelivery and --enable-valias
  - bug fix in mysql.h: wrong definition of VALIAS_TABLE_LAYOUT as it was looking
    for DEFAULTDELIVERY definition instead of DEFAULT_DELIVERY
  - configure.ac: solved all autoconf warnings

5.6.0 - Released 2023/12/11
  - Merge patches from FreeBSD:
    (Peter Pentchev <roam@FreeBSD.org>)
    - authvchkpw.c: Various sanity- and security-related fixes.
      Buffer handling:
        - use snprintf() instead of strncpy() to ensure null-termination;
        - explicitly pass sizeof(var) as a second argument to snprintf() to
          protect against a variable definition changing in the future;
        - display the correct amount of failed-to-allocate memory.
      Fix a misspelling of TCPREMOTEIP that would prevent POP-before-SMTP.
      Enclose a write() into a loop so that it succeeds even for amounts
        too large to write at once.
      Display an error message if the execv() in exec_local() fails and
        propagate the error all the way up to main()'s exit code.
      Extract the indiargs as separate defines so that the port's Makefile may
        modify them easily.
      Mark two function parameters as unused.
      Fix a couple of const-related compiler warnings.
    - backfill.c: String buffer handling fixes.
      - convert a strncpy() to snprintf() to ensure null-termination;
      - explicitly pass sizeof(var) as the second argument of snprintf().
    - vlist.c: Sanity and usage fixes.
      Do not impose an arbitrary limit of 100 list entries.
      Fix the usage message and an error message.
    - vlistlib.c: Sanity and safety checks.
      Honor lots of limits - convert sprintf() to snprintf(), use the correct
        limit size, etc.
      Check a couple more calls for errors.
      Wait for the correct child process - waitpid() instead of wait().
      Add two closedir()'s to fix file descriptor leaks.
      Look for the arguments properly if progname should ever containing spaces.   
    - vmysql.c: Fix the virtual alias support; implement SQL_REMOVE_DELETED.
    - vpalias.c: Honor the correct limits.
    - vpgsql.c: Implement valias support; implement SQL_REMOVE_DELETED.
    - vutil.c: Sanity and safety.
      Optimize a lot of calls by just using access(2).
      Fix a file descriptor and FILE structure leak.
    - README.vpopmaild: Fix a couple of typos and grammatical errors.
    - README.onchange: Fix a typo.
    - README.vdelivermail: Fix a typo.
        
    (Peter Pentchev <roam@FreeBSD.org>,
	 Alex Dupre <ale@FreeBSD.org>)
    - vpopmail.c: SpamAssassin support, sanity checks.
      Implement SpamAssassin support.
      Honor limits correctly.
      Wait for the correct child process - waitpid() instead of wait().
      Check for a couple more errors.
      Add a closedir() to fix a file descriptor leak.
    
    (Suzuki <xsuzu@yokohama.riken.jp>)
    - vldap.c: Fix a crash when adding a virtual domain.    
    
    (Alex Dupre <ale@FreeBSD.org>, 
     Peter Pentchev <roam@FreeBSD.org>,
	 Bryan Drewery <bdrewery@FreeBSD.org>)
    - vdelivermail.c: SpamAssassin support, build optimization      
      Add SpamAssassin support.
      Drop the unneeded MAX_ENV_BUFF definition.
      Add DELIVER_TO_STDOUT support    
  
  - Merge patches by Roberto Puzzanghera:
    - A patch to make vpopmail store domain aliases to MySQL. This gets 
      dovecot's sql auth driver aware of domain aliases, provided that you 
      modify the sql query accordingly.
      See doc/README.sql-aliasdomains for more info.
    - A patch which installs the sql procedure needed for the dovecot's 
      queries for servers with one table for each domains 
      (--disable-many-domains).
      You have to add --enable-mysql-bin to you configure command.
      The sql procedure is in the vpopmail-5.4.33/dovecot/ folder and it will 
      be copied to ~/vpopmail/etc/.
      It supports aliasdomains and user/domain limits.
      This feature does nothing if you have all domains in the vpopmail table 
      (--enable-many-domains).
      See README.dovecot-sql-procedures for more info.
    - A patch which makes vpopmail to copy you favourite delivery agent,
      stored in QMAILDIR/control/defauldelivery, in the mailbox's .qmail and
      the vpopmail delivery agent in the domain's .qmail-default.
      configure --enable-defaultdelivery (default is OFF) to enable this
      functionality.
      See doc/README.defaultdelivery for more info.
    - vusaged-configure patch
      It seems that at least on Debian 11 vusaged refuses to run the configure 
      successfully, as the mysql libraries are not linked with this error: 
      configure: error: No vauth_getpw in libvpopmail 
      After some inspection, I noticed that avoiding the break of the configure 
      command, the following make command will find libmysqlclient and compile 
      with no problems, and the program works as expected.
      NB: an "autoreconf -f -i" into the vusaged directory is needed before 
      configuring, as the configure.ac was modified.
    - A "recipient check" program to be used with E. Hoffmann's s/qmail.
      Look at doc/README.vrcptcheck for more info.
    - A patch which gets vpopmail to compile with gcc-10
    - vuserinfo-D_newline patch, which prints a new line to separate users'
      infos when typing "vuserinfo -D domain".
    - autotools and .gitignore changes to allow users to configure vpopmail 
      with no autoreconf. 
      I think this is important because the configure.in requires the latest 
      autoconf version.
    - defauldelivery patch bug fix: if defaultdelivery already contains 
      vdelivermail do not create .qmail

  - Merge patch by Ali Erturk TURKER
    - vdelivermail.c checks spamassassin permissions, instead of maildrop permissions.
    - vopen_smtp_relay() return values corrected, so that open_smtp_relay() can
      detect and report database connection errors (vmysql.c, voracle.pc, vpgsql.c )
    - vdel_limits() core-dumps if a database connection is not available beforehand.
      (vmysql.c, voracle.pc )
  
  - Merge patch by Johannes Weberhofer:
    - Fix strncat warnings

  - Merge patch by Benedikt Boehm:
    - Remove unneeded reallocation in vpalias.c

  - Merge patch from Gentoo:
    - Add missing include in cdb_seek.c

  - Merge patches by Rolf Eike Beer:
    - Fix printf format strings
    - Fix build when using PostgreSQL and --enable-onchange-script
    - Add test for crypt return value
    - Remove unneeded forward declaration in vchkpw.c
    - Add static in vdelivermail.c
    - Clean up calling maildrop in vdelivermail.c
    - fix ,S= tag in case spamassassin changed the file size
    - fix those vfork() instances that do more than exec*()

  - Merge patch by Jory Pratt:
    - patched for lazy binding for quality assurance

  - Merge patch from Ivan Zahariev:
    -  backfill algo fails if the username is contained anywhere in the file path 
      
  - Merge patch from Paul Oehler:
     - Fix bug in string_list_add when resizing the list
     
  - Merge patch from Nathanaël Semhoun:
     - Fixes for compiling without log on change, and fixe for included files
     - We need to remove | or ' ' before creating the args[] for sh, otherwise | 
       will be an argument of bash.
       
  Patrice Duhamel
  - Add an option --enable-onchange-script-before-and-after to call onchange
    script before and after a change
  - Add SQLite module, adapted from MySQL module code
  - Add an option --enable-sha512-passwords by default, and increase all 
    sql modules password size
  - Disable clear password option by default
  - Set vpasswd, vadddomain and vadduser default password length to 12, 
    and add optional password length in vpasswd
  - Fix crash in vpasswd, vadduser, vadddomain for very long password
  - Add an error code for too short passwords (minimum size = 12)
  - In vadddomain(): reject no TLD or invalid size TLD, or two consecutive '.'
  - Change max size of user name and gecos to 64, and increase temporary buffer
    in make_vpasswd_cdb to fix a crash after changing the user name size
  - Add fix from Roberto Puzzanghera: 
         - Fix mysql module compilation on Debian 11 / gcc 10
  - In vadddomain, remove domain if the postmaster user can't be created
  - Add minimum and maximum length of parameters in error messages
  - Add an option --enable-min-pwd-length to choose minimum password length
  - Add an option --enable-tinycdb to replace cdb code by libcdb
  - Add an error message in vpasswd, vadduser, vadddomain when using -r 
    and a password on command line
  - Allow -n in vadduser only if min password size = 0
  - Simplify calls to call_onchange, and add an option to log all changes
    to syslog or a sqlite database
  - add missing includes and compilation option for c99
  - fix ldap module compilation for recent openldap versions (untested), 
    and disable ldap sorting because it's not supported by openldap
  - add an option --enable-qmail-cdb-name to set qmail cdb file name, 
    after Erwin Hoffmann changed cdb name since s/qmail 4.2.03

5.4.33 - Released 10-21-2012
  Matt Brookings
  - Defaulted to Server::Disable=True in vusagec.conf
  - Fixed bug that didn't install vusagec.conf
  - Changed relevant quota code to use storage_t 64bit type
  - Fixed bug where backfill code wouldn't compile when FILE_LOCKING was
    enabled
  - Updated MySQL module to support larger quota sizes
  - Fixed typo
  - Added disable_maildrop flag to MySQL limits feature
  - More changes to allow for larger quota sizes in MySQL module
  - Updated to signal_process to understand "runsv" as a supervise-type process manager

  Tullio Andreatta
  - Dynamic allocation of valias data
  - Use of open/fchdir rather than getcwd/chdir to maintain current working
    directory
  - Fixed a broken symbolic link check

  Drew Wells
  - Modification to vdelivermail to properly handle Maildir paths that begin with "./"

  <kenji@kens.fm>
  - Removed call to maildir_addquota inside user_over_maildirquota causing duplicate
    maildirsize entries

5.4.32 - Released 11-08-2010
  Matt Brookings
  - Updated maildirsize creation to set uid/gid on target
  - Updated maildirsize_read to enforce Maildir++ specifications related
    to maildirsize filesize and maildirsize modification time.
  - Fixed returning of 0 rather than NULL in client_connect
  - Updated vusage client API not to try to connect to the daemon if
    vusagec.conf does not exist
  - Fixed quota calculation bug when delivering with vusage daemon

  aledr <matrixworkstation@gmail.com>
  - Patch to secure against possible overflows when reading ezmlm configurations

  <alessio@skye.it>
  - Patch to vpopmaild to fix return value in wait_read

5.4.31 - Released 12-10-2009
   Matt Brookings
   - Released to fix leftover issue that should have been addressed in 5.4.30

5.4.30 - Released 12-10-2009
   Matt Brookings
   - Fixed problem where variable was declared in-function
   - Duplicated a few fixes from 5.5 branch in vusaged

5.4.29 - Released 12-03-2009
   Matt Brookings
   - Numerous fixes to compile on Solaris
   - Fixed some format string issues
   - Fixed strstr being used with NULL value in vchkpw
   - Numerous fixes to compile on FreeBSD
   - Released to address some segfault issues in 5.4.28
   - Fixed bug in config API that assumes config pointer is not NULL
   - Updated client API to check Server::Disable
   - Updated client API to properly release configuration-related memory

5.4.28 - Released 08-24-2009
   Matt Brookings
   - Updated vlimits_read_vlimits_file to be much more efficient
   - Added vusage client API to libvpopmail
   - Added vusage daemon
   - Updated quota code to talk to vusage daemon if available
   - Fixed some backfill patch compilation issues
   - Updated maildir_to_email to support paths that end in /Maildir as well as /Maildir/
   - Added LDAP valias support
   - Updated vusage API to return counts for both users and domains
   - Updated domain quota enforcement to work when using vusage
   - Re-enabled --enable-domainquotas (with warnings)
   - Fixed percentage calculation bug in vmaildir_readquota
   - Updated lastauth/vlog queries not to trigger failure condition on domain
     deletion in MySQL and PostgreSQL module
   - Updated build scripts to show version 5.4.28
   - Added solution for 5.4.28 to LDAP schema for sn and cn attributes being
     required.  A permanent solution will be added to the 5.5 tree
   - Fixed vdelivermail to process .qmail files for users with dashes in their
     usernames when qmail-ext is enabled
   - Fixed bounds error in vauth_much_domain and increased buffer size for
     longer domain names
   - Applied same fix to PostgreSQL module

   aledr <matrixworkstation@gmail.com>
   - Fixed overflow in PostgreSQL module

5.4.27 - Released 16-Jan-2009
	Jeremy Kister, Rick Widmer, Tom Collins
	- Solaris doesn't like setenv

	Michael Johnson, Steve Cole, dhaval, Rick Widmer
	- Another attempt at maildirquota

        Harmut Wernisch, Tom Collins
	- Fix mixed up usage of MYSQL_UPDATE_* and MYSQL_READ_* in vmysql.c:load_connection_info()
	This may need a tracker number attached.  I can't find it.

    Manvendra Bhangui
	- Added authvchkpw module for Courier-IMAP
	- Added backfill patch [2507177]

5.4.26 - Released 3-Nov-2007
	Bill Shupp
	- vpopmaild fix: find_domain should not list 'page 0' when a domain is not
	found.  Instead, return "." only.  Also indicate in help that per_page is 
	optional.  find_domain page numbers consistently start at 1.
	- update README.vpopmaild to reflect the above.
	- Get valias_remove() working for cdb module.

	Rick Widmer
	- Arrange vpopmail.h based on libvpopmail categories
	- Add vlistlib library, vlist program to manage mail lists


5.4.25 - Released 9-Oct-2007
	Rick Widmer, Tom Collins
	- another try at signedness warnings in maildirquota and vchkpw
	- minor change in README.vdelivermail


5.4.24 - Released 29-Sep-2007
	Rick Widmer, Tom Collins
	- fix off_t warnings in maildirquota.c when mysql back end is used.

	John Simpson, Joshua Megerman
	- extend maximum password length


5.4.23 - Released 23-Sep-2007
	Rick Widmer
	- Upgrade build system to match my dev server  (SuSE 10.2)
	- Revert maildirquota warnings change


5.4.22 - Released 15-Sep-2007
        Steve Cole
	- invalid MySQL info in UPGRADE

	Bill Shupp
	- Missing ERR defines in vpopmaild.msg
	- Fix help text for add_ip_map and del_ip_map in vpopmaild.c

	Rick Widmer
	- attack warnings in maildirquota by making some variables unsigned everywhere

        Steve Cole, Marcello Lupo, Japheth Cleaver,  Rick Widmer
	- segfault in vdeluser with MySQL back end.  Work around applied, and note
	added to TODO about making database valias return .qmail files if they exist
	which is the long term fix.


5.4.21 - Released 06-Sep-2007
	Joshua Megerman, Alessio Cecchi
	- fix bug in vpopmaild add_alias command


5.4.20 - Released 21-Aug-2007
	Bill Shupp/Rick Widmer
	- add show_error function to vpopmaild 

	Rick Widmer
	- Make vadduser check that domain exists and user does not exist
	  before prompting for password
	- Add TODO file to record stuff I don't want to forget
	- Add README.vdelivermail 
	- Add examples for delete and bounce-no-mailbox to help on vadddomain

	Remo Mattei
	- Change upgrade script to use pw_domain instead of domain in example code
	  to change domain name field lengths.

	John Simpson, Joshua Megerman, Adam Sloan
	- Fix bad exit if script exists but can not be executed
	- Fix missing onchange on delete of alias domain

	John Simpson
	- Bug fix for vuserifo - vlimits
	
	Harm van Tilborg
	- Add support to vpopmaild to retrieve used storage sizes of domains or users
	- mod_user did not respond +OK if command is valid

	Vitali Malicky (coonardoo), Ismail Yenigul
	- add ldap patch [1909348]

	Ronnie Karstenberg (rkarstenberg)
	- vdominfo crashes with a lot of aliased domains [1765534]

5.4.19 - released 21-May-2007
	Rick Widmer
	- update to aclocal 1.9.5, automake 1.9.5, autoconf 2.59 to match my system
	- Don't set LocalPort to a real port number so the default case has a chance 
	  to identify how vchkpw was called.
	- ./configure tells status of onchange script setting
	- Fix rights problem with alias commands.  -  thanks Alessio Cecchi
	- Only report out of order entries when sorting files once per file
	- make pop syslog ./configure setting report itself like the rest of the choices
	- Make error messages more consistant (P/O checking Jonathan's bug report)

	Harm van Tilborg, Quinn Comendant
	- Do not allow delete of catchall address within account. [1511531]

	Bill Shupp
	- enable-onchange-script defaults to no.  
	  NOTE: Still need to supress error message if file not found.
	- Fix bug in output format of list_alias
	- Remove unneeded AC_DEFINE_UNQUOTED from ONCHANGE_SCRIPT in configure
	- Port remaining spamassassin code from 5.5 branch to stable-5_4.
	- Add new --enable-maildrop option, and new NO_MAILDROP bit flag. 
	- New Documentation: README.maildrop, README.spamassassin
	- Sample maildroprc files for both 1.x and 2.x (maildrop/*)

	Fabio Busatto
	- #include <stdio.h> at top of vpopmail.h


	blaze_cs
	- Ldap back end reads config parms from a file at runtime. [1056529][1476647]

        Stoyan Marinov (smarinov)
	- add %m$t style for SQL queries format string [1236349]
	- connect to mysql with a unix socket  [1437085]


5.4.18 - released 30-Dec-06

        Joshua Megerman (offsides)
        - SQL backend fixes - NOTE: Requires database changes.  
          See UPGRADE for 5.4.18.  [1619489]
        - MySQL Tablename Backquotes - Add back quotes around table
          names so MySQL will allow names that start with a digit.
          [1619491]

	Drew
	- add .qmail-extension ability to vdelivermail
	- mods to Delivered-To: header to support .qmail-extension

	John Simpson
	- onchange - call a script when users or domains are changed
          see README.onchange.
        - cslogin - Compact and silent login options for vpopmaild
          note: don't blame John for problems in this, I changed a
          lot to make it fit with other changes. rww

	Tijs Zwinkels
	- vmysql: add missing mysql_free_result to fix mem leak.

	Tom Collins
	- vdelivermail: Add missing loop check.
	- vchangepw: Minor changes to Peter's error checking. [1573277]

	Rick Widmer  (rwidmer)
	- Multiple changes to vpopmaild:
	  Add rename_file command.
	  Expert mode works in vmoduser.     
	  Commands that are not yet implemented say so.
	  Blank input lines are not an error in vpopmaild.
	  Separate help before and after login in vpopmaild.
	  Allow 3 tries to login to vpopmaild.
	  Clean up if add_user fails because of bad user data.
	  Add termination code (.) to get_lastauth return.
	  Number the error messages (XXX) in vpopmaild
	  If invalid option is sent in set_limits, show warning
	- Add various patches from others listed below:

	Peter Pentchev (roamer)
	- Various sanity checks and minor optimizations [1573292]
	- Fix child handling - waitpid and sys/wait.h [1573288]
	- Dynamicallly allocate sortdata[] in vpopmail.c [1573287][1596259]
	- Include ctype.h in the PostgreSQL backend [1573284]
	- Set SHELL in vdelivermail before executing external programs [1573280]
	- Some more error checking in vchangepw [1573277]
	- Improve the vpopmaild documentation [1573269]
	- Clean cdb files in the distclean target [1573267]
	- Optional building as non-root [1573266]

	Trent Lloyd (lathiat)
	- Add vailas add/delete/list support to vpopmaild [1555398]
	- Refresh assign cache if a domain is deleted [1529744]

	Bill Shupp
	- Add user_count function to vpopmaild
	- Add stat_file function to vpopmaild

5.4.17 - released 12-Jul-06

	Rick Widmer
	- vpopmaild: remove debug output from find_domain function.
	- vpopmail: fix segfault in users/assign sorting code caused by 
	  entries that don't contain a dot (.). [1514733]

	Jeremy Kister
	- vdelivermail: pass qmail-inject's error code instead of always
	  deferring. [1484105]

	Ron Gage
	- vmysql: reconnect to server if connection timed out.

	Rolf Eike Beer
	- vchangepw: add error checking and other code improvements.
	  [1371572]
	- change API for vgetpasswd() to make more sense. [1371566]
	- Update del_control() to properly handle remove_lines() return
	  value. [1514613]
	- vpopmail: minor improvements to remove_lines(). [1371536]

	secnetdk
	- vmysql, vpgsql: remove entries from vlog when deleting a domain
	  or a user. [1099800, 995762]

	Michael Krieger
	- vcdb, vpopmail: pass mode to open() when creating files.  Fixes
	  bug where lock files were created with 0000 permissions. [1499043]
	- vpalias: set mydir to NULL after closing it. [1499045]

	Tom Collins
	- vpalias: don't trash alias name passed to valias_insert().
	  [1491087]
	- vpopmaild: don't show last auth if auth-logging disabled.
	  [1511313]
	- Only include err.h if it's present. [1484110]
	- vpgsql: convert domain name to lower case when creating table
	  name. [1227383]
	- vpopmail: fix minor error in remove_lines() when file locking
	  not defined.

5.4.16 - released 7-May-06

	Michael Krieger
	- vpalias: Properly handle some empty search results.

	Ken Jones
	- vpalias: wasn't allocating enough memory for alias name in
	  valias_select_names (missing one byte for NULL). [1479842]

	Jianbin Xiao
	- vmysql: reconnect to server if connection was dropped.
	  [1469731]

	Rick Widmer
	- vpgsql: fix queries to allow domains starting with digits.

	John Simpson
	- vpgsql: fix compile errors introduced in 5.4.14.
	- vdominfo: undo change from 5.4.14 that displayed alias domains
	  incorrectly.

	Toshihiko Kyoda
	- vdelivermail: check for over quota when creating temp mail file.

	Tom Collins
	- vpalias: Fix double-free in code ported from 5.5 branch.
	- valias: exit non-zero on error, send all errors to stderr.
	- vchkpw: make sure we have cleartext pass before checking SMTP_AUTH
	  or APOP logins. [1453216]
	- Remove vactivedir code since it's just a client for a non-existent
	  server.

5.4.15 - released 24-Feb-06

	Tom Collins
	- Add 'compile' script to distribution.
	- If warn() isn't available, use fprintf() instead.
	- vmysql.c: add missing valias_select_names, valias_select_names_next,
	  and valias_select_names_end from 5.5 branch.
	- vpalias.c: #include "config.h" before we check if VALIAS defined.

5.4.14 - released 17-Jan-06

	Tom Collins
	- vmysql.c: Increase buffer size in vauth_adduser() and use 
	  correct size when calling snprintf.
	- Backport most of 5.5.1, including code required for vpopmaild.
	- Allow --enable-valias option for Postgres backend (incorrectly
	  disabled in 5.4.13).
	- Only check a domain's disk usage when a quota is set. [1396238]

	Bill Shupp
	- vpopmaild: store quota in proper format and update maildirsize 
	  on quota change.

	Gaetan Minet
	- Remove lock file in open_smtp_relay() even if update_rules() fails.

	Rick Morris
	- vdelivermail.c: Fix problem where "# delete" in .qmail file was
	  being ignored. [1360346]

	Robin Bowes
	- Add vpopmaild (the vpopmail daemon) from 5.5 development series.

5.4.13 - released 16-Sep-05

	Riccardo Bini
	- vdelivermail.c: Use DOMAINS_DIR instead of hard-coded "domains".

	Jory A. Pratt
	- Compile libvpopmail with -fPIC option so amd64 users can compile
	  courier-authlib against libvpopmail.a.

	Tom Collins
	- hmac_md5.c: include <strings.h> for bzero and bcopy declarations.
	- configure.in: fix checks to limit enable-valias to MySQL only.
	- INSTALL: make clear that valias only applies to MySQL backend.
	- vpopmail.c: modify get_remote_ip() to work with xinetd, not
	  just tcpserver from daemontools.

5.4.12 - released 4-Jul-05

	Tom Collins
	- vdelivermail: read full message, even on catchall delete/bounce
	  to avoid SIGPIPE error if maildrop is calling vdelivermail.
	- vdelivermail: missing declaration when QMAIL_EXT defined.
	- vpopmail.h: remove declaration of crypt() and use #include 
	  crypt.h instead (if present).
	- configure: remove enable-domainquotas option until the domain
	  quota code is fixed.
	- maildirquota.c: fix bug from 5.4.11 that could accidentally
	  close stdin and result in a failed delivery in vdelivermail.
	- vpopmail.c: better error checking in r_mkdir().

5.4.11 - released 20-Mar-05

	Tom Collins
	- vdelivermail: code cleanup (fix exit codes, improve reliability,
	  fix problems with quotas). [837146, 840749, 904155, 1111291,
	  1119741, 1145618]

5.4.10 - released 20-Mar-05

	Stephan Tesch
	- md5.h: fix related to segfaults in vchkpw on Sparc64. [1144851]

	Peter Seiderer
	- vcdb.c: vauth_getpw() didn't check for invalid domain.

	Bill Shupp
	- vuserinfo: display spamassassin info.

	Anonymous
	- vpopmail.c: Add missing ifdef that preventing modification of
	  one-character username accounts.

	Niki Denev
	- maildirquota.c: Remove double free() and fix use of free'd
	  memory in docheckquota(). [1101316]
	- contrib/qmail-maildir++.patch: same fix as for maildirquota.c.

	Tom Collins
	- vlimits.c: print errors to stderr.
	- vmoduser.c: add clarity to usage/help for bit flags.
	- vcdb.c: be sure to close password file in vauth_getpw().
	- md5.h: use cdb/uint32.h (built by configure)  for defining 
	  uint32. [1144851]
	- vpopmail.c: fix vauth_user() to not clobber pw_uid and pw_gid.
	- vpopmail.c: If setting user quota for new user fails because newly
	  created user does not exist, sleep 5 seconds and try again.  
	  (This can happen on servers using MySQL replication.)
	- Remove convert/vcalias.c and related files; vcalias was replaced
	  by dotqmail2valias.

	Michael Bowe
	- configure.in: fix typo of where the configure script says it
	  is checking for qmail-inject when in fact it was checking for
	  qmail-newmrh 
	- Documentation updates to README.roamingusers. Mention the 
	  requirement of tcpserver for POP-before-SMTP. Also include
	  some documentation on IMAP-before-SMTP. [1110269]

5.4.9 - released 26-Dec-04

	Jeremy Kister
	- Makefile.am: fix install problem on Solaris.  Some .h files
	  weren't being installed correctly.

	Charles Boening
	- Fix logging in PostgreSQL.
	- Change ENABLE_{MY|PG}SQL_LOGGING to ENABLE_SQL_LOGGING.
	- Replace --enable-{my|pg}sql-logging with --enable-sql-logging
	  in configure options.

	Tom Collins
	- Tweaking of Charles Boening's changes.
	- vchkpw: Fix problem in md5.h causing segfault in SMTP AUTH on 
	  amd64. [964843, 958799]
	- vpopmail.h: Add new error and flag defines from 5.5 series.
	- vchkpw: log webmail connections as 'vchkpw-webmail'.
	- vpopmail.c: fix problem related to sending SIGHUP to qmail-send.
	  Original problem could cause "Signal 1 caught by ps" error.

5.4.8 - released 12-Nov-2004

	Rick Widmer
	- vadddomain: Check for existing domain before prompting for
	  password.
	- vdeldomain: Fix uninitialized variable warning.

	Tom Collins
	- Fix problems with valias code in vmysql.c and vpgsql.c.  Storing
	  aliases in Postgres should work now, and it should fix problems
	  with processing Maildir valias entries in vdelivermail. [985011,
	  1024706, 1033801]
	- Fix bug in vmoddomlimits that wiped out the Domain Quota 
	  when editing default limits.
	- Change columns in Postgres valias table to varchar from char.
	  See README.pgsql for instructions on fixing existing tables.
	- vmoduser: update maildirsize instead of just deleting it when
	  modifying quota.
	- vchkpw: classify POP/IMAP connections from select IPs (defaults
	  to 127.0.0.1) as webmail and check NO_WEBMAIL user flag instead
	  of NO_POP and NO_IMAP.
	- Update qmail-smtpd-auth patch in contrib to latest (0.5.6).
	- Update README.quotas with note about domain quotas not working.
	- vpopmail.c: remove unused sys/varargs.h include.
	- vdominfo: fix broken -a option.
	- vdominfo: better display of real name for alias domains. [981335]
	- vpopmail.c: Improved maildir_to_email() function. [953439]

	Gentoo Port
	- Integrate vuserinfo patch to fix the -a option and to display 
	  the comment/gecos field (used for "real name").

5.4.7 - released 23-Sep-04

	Michael Bowe
	- Mention in README.mysql that is is possible to create mailboxes 
	  by inserting entries directly into the MySQL table.

	Tom Collins
	- Don't try to delete dir-control for domain unless users-big-dir
	  is enabled.
	- Verify user exists before trying to set quota in vsetuserquota().
	  [984698]
	- Update cdb/Makefile so you can 'make install' without doing 
	  'make' first.
	- Fix size comparisons to MAX_PW_X (should be ">", not ">=").
	- Fix possible buffer overflows in vsybase.c.
	- Have vconvert reset dir_control and increment it for each user
	  added when converting from cdb to MySQL.
	- If crypt() doesn't support MD5 passwords, fall back to using
	  a valid, non-MD5 salt even if MD5 passwords are enabled.
	- Fix format string vuln. in vactivedir.c (thanks D4rk Eagle).
	- Added comment to vqmaillocal.c mentioning that it isn't
	  maintained and probably doesn't work.  Makefile no longer
	  installs vqmaillocal.

5.4.6 - released 30-Jun-04

	[backport from 5.5.0]
	- Consolidate table creation code in vmysql.c and vpgsql.c.
	- Increase SQL_BUF_SIZE from 600 to 2048 for Oracle, Postgres
	  and Sybase.
	- Multiple fixes to vpgsql.c related to freeing PGresults and
	  attempting to access NULL PGresults when reporting errors.
	* These changes address SQL Injection vulnerability documented in
	* Bugtraq ID 10990 <http://www.securityfocus.com/bid/10990/info/>
	- Add qnprintf() to vpopmail.c for escaping strings in SQL queries.
	- Use qnprintf() when building queries in vmysql.c, vpgsql.c,
	  voracle.pc, and vsybase.c.

5.4.5 - released 25-Jun-04

	fernando (at) telemacro (dot) com (dot) br
	- Patch for vpgsql.c fixes bug with Postgres and roaming users
	  (POP before SMTP). [895501]

	Françoi Wautier
	- Fix method used to open database in vauth_open_update of
	  vmysql.c. [967994, 946983]

	Pit Palme
	- Show 'delete' as valid option to vdelivermail in docs. [951245]

	rstml
	- Hide error message during POP3 auth with Postgres. [915485]

	Tom Collins
	- Fix `vuserinfo -l` output, based on Bill Shupp's patch
	  (moved code to a single function call). [961742]

5.4.4 - released 26-May-04

	Tom Collins
	- Link math lib when compiling for MySQL.
	- Create ~vpopmail and ~vpopmail/etc in configure script. [930939]
	  Note that any code creating files in ~vpopmail should probably
	  be moved from configure and into Makefile (under make install).
	- Use MAX_PW_DIR when checking max size of domain's directory.

	Ken Jones
	- vdelivermail.c: wait on pid for qmail-inject to finish
	  before continuing in deliver_mail function. [from 5.5.1]

        Michael Bowe
        - Minor documentation tweaks
        - Fix for : If roaming users were enabled, and auth module was not
          SQL based, and user's IP address was not available (eg being
          called from Courier-IMAP with authdaemon enabled), then
          open_smtp.tmp.pid files would be created for each auth 
          but never removed.

5.4.3 - released 11-Mar-04

	Tom Collins
	- Add missing link libs (m, nsl, socket) on Solaris installs.
	- Fix vsetuserquota() to write properly formatted quota to 
	  maildirsize file.
	- Update vdominfo to ignore non-domains in users/assign.
	- Update vconvert and dotqmail2valias to ignore non-domains in
	  users/assign.

5.4.2 - released 22-Feb-04

	Tom Collins
	- Remove attempts to free() static buffers in vpgsql.c. [888888]
	- Fix problems with creating valias table in vpgsql.c. [892595]
	- Remove unnecessary check for C++ from configure[.in].
	- Don't include DESTDIR when building inc_deps and lib_deps.
	  [886988]
	- Properly parse Maildir and mbox delivery lines in .qmail files
	  in vdelivermail (and exit(111) for mbox lines). [889756]
	- Temporarily disable -s option to vadduser (since it's broken).
	  [895375]

	Anders Brander
	- Add contrib/checkpassword_debug.[README,c] for testing and
	  debugging problems with vchkpw. [862608]

5.4.1 - released 10-Feb-04

	Tom Collins
	- Add dotqmail2valias program for converting .qmail-alias files
	  to valias table entries.

5.4.0 - released 1-Feb-04

	Tom Collins
	- Update configure with correct location of vlimits.default.
	- Fix typo (ammount) in vmoddomlimits. [882884]
	- Don't include $(DESTDIR) when building vpopmailbindir. [884247]
	- Mention compatability issues with older SMTP AUTH patches. 
	  [882351]

5.4.0-rc2 - released 19-Jan-04

	Michael Bowe
	- Added some basic 5.4 upgrade notes to the UGPRADE file
	- Fix typo's in configure.in that relate to the errors generated
	  when a discontinued configure option is used
	- Fix bug when autocreating a user dir for a user who exists
	  in the auth backend, but does not yet have a user dir 
	  allocated. [873007] 
	- Fix bug introduced in vpopmail-5.4.0-pre2 that was preventing
	  ~vpopmail/etc/vpopmail.mysql from being installed [874776]
	- vpopbull was failing to create userdirs in some cases
	  (when the user exists in the auth backend, but did not have
	  a dir allocated yet) [816942]
	- clearopensmtp was using USE_MYSQL rather than USE_SQL to 
	  determine where the roaming IPs were being stored [876016]
	- Update INSTALL and other guides to mention that vchkpw group
	  does not need to be gid 89. [877154]
	- Update README.pgsql to include security warning regarding
	  the postgres username/password [879124]

	Ken Nonaka
	- Fixes to vpgsql.c to clear compile errors when 
	  --enable-ip-alias-domains is enabled. [874066] 

	Tom Collins
	- Check for comments earlier in deliver_mail().
	- Remove unused --enable-defaultquota and code related to it.
	  (Replaced by settings in vlimits.default.) [869411]
	- Remove references to --eanble-defaultquota in documentation.
	- vdelivermail.c: Consistent return values in deliver_mail().
	- More updates to build files. [874831]
	- Apply patch from http://www.fehcom.de/qmail/smtpauth.html
	  to fix CRAM-MD5 SMTP AUTH in vchkpw. [871493]
	- Have vchkpw.c use get_remote_ip() to convert IPv6 to IPv4
	  (fixed problem with ::ffff: in relay file). [876019]
	- Fix bug in vpalias where .qmailadmin-limits was incorrectly
	  thought to be alias for user 'dmin-limits'.
	- Sort by alias in valias_select_all (needed for QmailAdmin).
	- Add new valias_remove() command to remove a single line from
	  valias table.  (not implemented for cdb backend yet)
	- Fix incorrect buffer use in PQexec() calls.
	- Convert '.' to ':' when building filename in valias_select()
	  in vpalias.c.
	- Remove length check for 'alias' parameter in vpalias.c's
	  valias_select_all() and valias_select_all_next() since it's a 
	  return value buffer.
	- Remove duplicate code in valias_select_all_next() in vpalias.c.
	- Fix configure.in to update cdb/conf-cc and cdb/conf-ld. [877166]
	- Add /usr/local/mysql/include/mysql to search list for incdir,
	  and /usr/local/mysql/lib/mysql for libdir. [877168]
	- Remove cdb/compile, cdb/load, cdb/conf-cc and cdb/conf-ld as
	  they are automatically generated during configure/make.
	- Add missing $(DESTDIR) to some @vpopmaildir@ paths in Makefile.
	  [879103]

	Bill Shupp
	- Add -o option to vmoduser to set V_OVERRIDE flag. [875505]
	- Contributed README.vlimits [855693]
	- Updated README.quotas

	Casey Zacek
	- Create maildirsize file in vsetuserquota(). [869457]

	Anders Brander
	- Allow optional length for random passwords in vadduser and
	  vadddomain. [848228]

5.4.0-rc1 - released 1-Jan-04

	Michael Bowe
	- Code fixes and documentation work for LDAP module. 
	  Incl updated README.ldap, vldap.c, vldap.h, ldap/slapd.conf, 
	  ldap/vpopmail.ldif. [863881] [811000] [864643]
	- Rewrote the README.mysql based on my web based guide.
	- Documentation tweaks for README.pgsql, README.roamingusers.

	Tom Collins
	- Remove unused var (cp), change random/srandom to rand/srand in
	  vpopmail.c to remove compiler warnings.
	- Fix Makefile to use correct owner/group/permissions for 
	  install-strip.
	- Fix configure to indicate that --enable-auth-logging is default.
 
5.4.0-pre2 - released 21-Dec-03

	*** Note that the configure option for setting the authentication
	*** module has changed.  Instead of --enable-mysql, use
	*** --enable-auth-module=mysql.

	Casey Zacek
	- Keep vlimits_setflags() in vlimits.c when mysql-limits is
	  enabled. [858109]
	- Create maildirsize file when adding new user. [858994]

	Tom Collins
	- open_smtp_relay(): fix address conversion of '::ffff:127.0.0.1'
	  ip format, move code to function and replace calls to
	  getenv("TCPREMOTEIP"). [858586]
	- When optimizing adddomain, rebuild users/cdb after each addition
	  instead of postponing. [859707, temporary fix]
	- Move maildir_to_email() from vdelivermail.c into vpopmail.c,
	  replace dupe code that tries to do the same thing. [859098]
	- Fix domain quota checks to work with hashed directories. [859098]
	- Fix bug when calling format_maildirquota() with NOQUOTA.
	- Document use of NOQUOTA in vadduser. [862315]
	- Fix Makefile so `make install` works from checked out CVS. [863862]

	Michael Bowe
	- Revise configure script so choice of auth module is now "OR" 
	  rather than "AND". 
          Auth module selection now uses the format :
            --enable-auth-module=cdb|mysql|pgsql|ldap|sybase|oracle|activedir
	  Rather than :
	    --enable-mysql --enable-pgsql --enable-ldap etc
	  If the old style is used, then the configure script will output
	  and error and will advise the user of the updated syntax. [855691]
	- Removed the code that created a vpopmail.config.sh file each
	  time the configure script is run. This file is never used,
	  and a more accurate result can be achieved by using
	  ./config.status --recheck [860271]
	- Update the vldap/qmailUser.schema so that it contains the 
	  required definition for 'clearPassword' [810999]
	- Modify vpopbull, so that within each domain, the users are
	  processed alphabetically. The idea behind this is to give the
	  operator some idea of "how far through" the mailout we are.

5.4.0-pre1 - released 10-Dec-03
	
	Michael Bowe
	- Updated README.xxxauthbackend files to include indication
	  of which auth systems are of production quality (cdb, mysql),
	  which ones are believed to be generally functional (ldap,
          pgsql) and which ones are not recommended (oracle, sybase,
	  activedir) [832302]
	- Review the assorted text files included in the source dir.
	  Remove out-of-date content / files as appropriate. Updated
	  some minor typos in the documentation [793659]
	- Contributed the README.roamingusers file that provides some
	  explanation of how the vpopmail roaming users system works.
	- Revised the configure.in script to try and improve logic,
	  formatting, and helpstrings. Also added tests for many new
	  functions/libraries as per suggestions from autoscan tool.
	  [828680]
	- Contributed README.ipaliasdomains file that provices some
	  explanation of the how the vpopmail IP Alias Domains system
	  works
        - Modified vdeldomain() so that it emits a warning rather than
	  aborting should any of the steps in the delete process fail.
	  The idea is to allow a partially installed domain to be 
	  cleanly and easily removed from the vpopmail system [821972]

	Tom Collins
	- Update more files involved in the build process.
	- Remove unused variable (fs) from vset_limits() in vlimits.c.
	  [846509]
	- Change permissions on vpopmail.mysql to 0640. [848605]
	- vuserinfo: indicate whether limit came from domain limits.
	- Correctly apply domain limits to user accounts.
	- Fix problem in maildirquota.c where off_t was assumed to be
	  long.  Created wrapper function to do conversion. [797011]
	- Fix double-printing of email address with vpopbull -V.
	- vpopbull: Fix incorrect link building when file starts with '/'.
	- vpopbull: Send errors to STDERR.

5.3.30 - 20-Nov-03

	Michael Bowe
	- Fixed logic error in update_rules(), to prevent "update_rules
          failed" error being generated on the first attempt for a 
	  roaming user to POP auth [833926]   
	- Remove "id" column in PostgeSQL's vpopmail table.
	  This column appears to serve no purpose, and causes errors
	  when you try to insert your first domain [822181]
	- Added installation instructions for PostgreSQL to the
	  README.pgsql file [824088] 
	- Made the default ~vpopmail/etc/vpopmail.mysql file more
	  verbose/descriptive
	- Cleared two bugs in the vauth_getall() funcion of vpgsql.c
	  These bugs were in particular causing qmailadmin not to be
	  able to display a list of users for a domain [837139]
	- Modified ifdefs throughout suite to clear compile failures
	  with some of the auth backends if you configured with 
	  --enable-auth-logging=n [842393]

	Tom Collins
	- Install a vlimits.default file if none exists (fixes "can't
	  read domain limits" errors). [828428,828658]
	- Allow for comments in vlimits.default and .qmailadmin-limits.
	- Ignore K/KB/M/MB modifiers on vmoddomlimits -Q. [821892]
	- Update help for vmoddomlimits to indicate that -Q is MB.

	Justin Heesemann
	- Add -d option to vmoddomlimits to work with vlimits.default.
	- Fix bitwise AND when setting pw_gid.
	- Fix bug when setting NO_DIALUP. [833926]

	Bill Shupp
	- Set uid/gid when creating maildirsize in vuserinfo. [832588,832592]

	Dmitry Vodennikov
	- Save/restore current working directory before/after calling
	  vdelfiles() in vdeldomain(). [835724]

	Rolf Eike Beer
	- Fix some prototypes and typecasts in maildirquota.c to allow for
	  compilation with cc on HP-UX 11.00. [840001]
	- Add vchangepw program to allow any user to change their password
	  (modified from vpasswd). [840001]

5.3.29 - 20-Oct-03

	Michael Bowe
	- Fix formatting error in tcp.smtp.tmp.pid filename
	  (was being created as tcp.smtptmp.pid).

	Tom Collins
	- Remove acconfig.h; update configure.in to work without it.
	- Update 'missing' script with version from automake 1.6.
	- Send errors to stderr instead of stdout (vpopmail, vchkpw).
	- Add support for port 587 (submission) to vchkpw.
	- Increase size of VchkpwLogName in vchkpw.c to eliminate a
	  buffer overflow.
	- Improve seeding for rand() and random() in vpopmail.c
	- Add -r (random password) option to vpasswd.
	- Better detection of connection type in vchkpw.c. [818943]
	- Remove extraneous calls to mysql_store_result(). [809472]
	- Minor cleanup of make_user_dir() in vpopmail.c.
	- Don't prompt for password in `vadduser -e ...`. [822308]
	- Set quota to default when adding new users. [821995]
	- vpgsql.c vauth_getpw(): Put in_domain on the stack. [822175]
	- Fix vget_limits calls. [824067, 824070]
	- Update example for --enable-tcpserver-file in configure. [824077]
	- Fix loop checking on Delivered-To header. [826231]

	Justin Heeseman
	- Set pw_flags field based on pw_gid and domain limits. [795688]
	- Use pw_flags instead of pw_gid to check permissions.
	- Allow K/KB/M/MB modifiers on vmoddomlimits -Q. [821892]

5.3.28 - released 3-Oct-03

	Michael Bowe
	- Remove vget_real_domain() declaration from vpopmail.h. [800738]
	- Fix compile errors with vpgsql.c. [801528]
	- Add code to configure.in to search for pg_config. [801528]
	- Re-add vget_real_domain() to vpopmail.h and vpopmail.c [800738]

	Oden Eriksson
	- Fix wrapped line in contrib/qmail-maildir++.patch.

	Tom Collins
	- Update vmoddomlimits to use format_maildirquota().
	- Fix compile errors with LDAP module. [802277]
	- Include vlimits.h in Active Directory and Sybase auth modules.
	- Update vpopbull to skip alias domains. [790778]
	- Look for MySQL in /usr/local/mysql/{include,lib} during configure.
	- Added pw_flags to vqpasswd struct, still need to update code.
	- Return error if link fails at end of deliver_mail().
	- Fix vdeldomain() to delete things in the correct order. [805703]
	- Update Makefile.am to create bin/doc/etc/include/lib with
	  correct owner/permissions if not already present.
	- Send errors to stderr instead of stdout (vmysql, vcdb, vpgsql).
	- Set umask before opening vpasswd.cdb.
	- Start adding CVS ID tags to each file.
	- Replace vgen_pass() with vrandom_pass() which doesn't leak
	  memory. [793662, 803950]
	- Fix broken dupe-alias checking code in valias. [807935]
	- Update Makefile.am to write all libs to etc/lib_deps. [796524]
	- Exit non-zero for non-existent alias with `valias -s <alias>`.
	- Properly append /Maildir/ to catchall in vdelivermail.c. [816336]

	Kazuho Oku
	- Fix qmail_inject_open() in vdelivermail to work with addresses 
	  that start with a hyphen (-). [805907]

	Anders Brander
	- Fix mkpasswd3() to use 8-char MD5 salt (instead of 5-char).
	  [804266]
	- Allow for swapped parameters to vaddaliasdomain. [812150]

5.3.27 - released 4-Sep-03

	Michael Bowe
	- Now that MySQL prefs are stored in a separate file, set 
	  permissions on libvpopmail.a to 644 to allow non-root users
	  to compile apps like courier-imap. [795773]
	- Include [RBLSMTPD=""] in tcp.smtp updates under MySQL and
	  PostgreSQL for consistency with cdb. [795793]

	Tom Collins
	- Fix Makefile.am to use short options for better cross-platform
	  compatability.
	- Update privileges on vpopmail.mysql during install.
	- Added 'make fix-priv' to update ownership of ~vpopmail/domains.
	- Move creation of inc_deps and lib_deps to Makefile.am from 
	  configure.in.
	- Fix vgetent() in vpopmail.c. [799466]
	- Move date_header() from vdelivermail.c to vpopmail.c for
	  shared use with vpopbull.c.
	- Print "Date: " header in messages sent with vpopbull. [790776]
	- Make sure files created by vpopbull are owned by vpopmail.vchkpw
	  and have 0600 permissions. [800030]
	- In valias, don't allow user to create duplicate alias. [796527]
	- Update quota parsing code and centralize to format_maildirquota()
	  in vpopmail.c. [775757]
	- Update vsetuserquota.c to use vsetuserquota() in vpopmail.c.
	- Update vmoduser.c to use format_maildirquota() in vpopmail.c.
	- Fix -r option in vadddomain. [800212]

	Jorge Valdes (patch from 10-Apr-2003)
	- Allow vpopbull to run without -f option if -n is used.  This
	  allows `vpopbull -n -V` to display a list of users. [798034]

5.3.26 - released 26-Aug-03

	Michael Bowe
	- Recoding work with the main focus of :
		* Ensuring strings are null terminated
		* Checking the return value of important function calls
		* Eliminating buffer overflow opportunities
		* Adding comprehensive comments to source files
	  Files that have been reviewed so far :
		clearopensmtp.c, vaddaliasdomain.c, vadddomain.c, vadduser.c,
		valias.c, vconvert.c, vdeldomain.c, vdeloldusers.c,
		vdeluser.c, vdominfo.c, vipmap.c, vkill.c, vlimits.c, 
		vmkpasswd.c, vmoddomlimits.c, vmoduser.c, vpasswd.c, 
		vpopbull.c, vpopmail.c, vsetuserquota.c, vuserinfo.c
	  Files that still require a review :
		vactivedir.c, vcdb.c, vchkpw.c, vdelivermail.c, 
		vldap.c, vmysql.c, vpalias.c, vpgsql.c, vqmaillocal.c, 
		vsybase.c	

5.3.25 - released 26-Aug-03
	*** WARNING: MySQL settings are now stored in         ***
	*** ~vpopmail/etc/vpopmail.mysql instead of vmysql.h! ***
	*** Read README.mysql for details.                    ***

	Tom Collins
	- Fix code in vdelivermail.c that builds Delivered-To header on
	  catchall emails.  (strips "domain-" from "domain-user@domain")
	  [785604]
	- Convert vpgsql.c from DOS to Unix format (strip \r). [785680]
	- Modified Makefile.am to allow installs to /usr/local instead
	  of /home/vpopmail (uses install, doesn't chmod/chown). [787551]
	- Polished vpopmail-5.2-vmysql.patch ported by Oden. [791405]
	- If configured to use MySQL, Makefile.am creates a sample
	  vpopmail.mysql if one doesn't exist and makes it read/write for
	  vpopmail.vchkpw only.
	- Added tracker item numbers to ChangeLog for all closed trackers.
	- Updated INSTALL and FAQ with links to SourceForge.

	Oden Eriksson
	- Ported vpopmail-5.2-vmysql.patch to 5.3.24. [778502, 791405]
	- Added sparse documentation how to use it.

	Justin Heesemann
	- Fix vdominfo to show correct domain for alias domains when
	  displaying all domains. [785241]
	- Add vmoddomlimits program to modify domain limits.  Works
	  for both vlimits and .qmailadmin-limits methods.
	- Add V_OVERRIDE user flag for users who aren't affected by
	  domain limits (.qmailadmin-limits or vlimits).
	- Update authentication modules to apply domain limits to users.
	  (Currently disabled pending solution to SF BUG 795688.)

	Evren Yurtesen
	- Add cleartext support to vconvert (when converting MySQL to
	  cdb). [785690]

	Michael Bowe
	- More cleanup in vget_assign() calls. [785735]
	- Allow vget_assign() to return real domain when passed alias.
	  [785682]
	- Fix error messages in vmysql.c. [792959]

5.3.24 - released 6-Aug-03

	Tom Collins
	- Removed all references to timezone to be POSIX compliant.  Now
	  uses gmtime() with +0000 for date header. [777401]
	- Fixed bug in my updated vget_assign that caused segfaults
	  in many cases (including vadddomain and vdeldomain). [777980]

	Michael Bowe
	- Update vget_assign calls with NULL directory pointer to use 
	  0 for buffer size. [774525]
	- Add missing backslashes (\) to vpgsql.h (see 5.3.21 vmysql.h).
	  [777923]
	- Check for NULL return when calling vauth_getpw() in vldap.c.
	  [781882]

	Charles Boening
	- Update configure.in to work for pgsql compiles. [777851]
	- Add --enable-pgsql-logging configure option. [777851]
	- Add vauth_crypt() to vpgsql.c. [777851]

	Yann St. Arnaud
	- Remove #ifdef FOOB from vchkpw.c to re-enable 
	  ENABLE_LEARN_PASSWORDS feature. [783824]

	Jens Jahr
	- Support for clear text passwords when using LDAP. [783908]

	Oden Eriksson
	- Remove unnecessary errno declaration in cdb/cdb_seek.c. [784024]

	Evren Yurtesen
	- Added contrib/sendmail2vpopmail.pl for converting from sendmail
	  aliases and virtusertable entries to vpopmail domains.

5.3.23 - released 25-Jul-03

	Tom Collins
	- Removed timezone declaration to correct compile problem on 
	  FreeBSD. [777401]

5.3.22 - released 24-Jul-03

	Moshe Jacobson
	- Fix maildir_to_email() to work with hashed domain directories.
	  [773315]

	Matt Berardi
	- Add 2 second timeout on MySQL connections.

	Jens Jahr
	- Check for failure when calling auth module.
	- Fix vadddomain/vdeldomain when the auth module call fails.
	- Fix vsetuserquota to include status messages.

	Tom Collins
	- Add Date header to over quota warning message. [773318]
	- Fix possible buffer overflows when setting envbuf[1-4] in 
	  vchkpw.c. (bug spotted by Michael Bowe) [774528]
	- Remove error messages from vmysql.c that could interfere with
	  POP or SMTP AUTH client sessions.
	- Switched from using --enable-default-domain to storing default
	  domain in ~vpopmail/etc/defaultdomain.  This should provide
	  flexibility when compiling packages for distribution. [775751]

5.3.21 - released 17-Jul-03

	Ole Gjerde
	- Check return code from vdeliver_mail in valias code and exit
	  appropriately on errors.  Previously, mail could be lost.

	Cory Wright (and others)
	- Fix missing "\" in multi-line #define in vmysql.h.

	Maurice Snellen
	- When logging POP3 logins, now includes system accounts.

	Emris
	- Ignore comments when processing .qmail files.

	Moshe Jacobson
	- Allow colons in cleartext passwords (vqpasswd() in vpopmail.c).

	Jonas Thomsen
	- Ignore final '.' in users/assign when running 'vconvert -c -m'.

	Michael Bowe
	- Remove debug printfs from vdelivermail on overquota bounces.
	  [773312]

	Jeff Hedlund
	- Ignore comments when processing .qmail files.
	- Process .qmail file when delivering to local (Maildir) catchall.
	- vdelivermail now properly sets $EXT@$HOST and sets Deliver-To
	  header on local deliveries.

	Tom Collins
	- Fix usage formatting on vconvert.
	- Support for MB/KB quota formats in vmoduser.

5.3.20
4/01/03  Tom Collins 
         - If there isn't a limits entry for the domain in MySQL, it uses 
           potentially random settings (nothing initializes the limits 
           structure).  I've updated a few files so that vget_limits in 
           mysql.c initializes the limits structure to defaults before 
           attempting to load from the database.

3/26/03  Ken Jones
         - add -D flag to vmoduser to change the directory

3/25/03  James Raftery
         -  Change -e flag behaviour for vadddomain.
            -e contains an @: forward as normal
            -e without an @: treat as name of user into whose Maildir to deliver
            e.g.:
            -e postmaster@forward.com
               fridge# cat forward.com/.qmail-default
               | /usr/local/vpopmail/bin/vdelivermail '' postmaster@forward.com

            -e postmaster
               fridge# cat maildir.org/.qmail-default (all on one line)
               | /usr/local/vpopmail/bin/vdelivermail '' 
                 /usr/local/vpopmail/domains/maildr.org/postmaster

3/24/03  Tom Collins 
         - Update vmoduser.c to write quotas out in the proper format.
           Automatically convert xxM and xxK formats to # of bytes.
         - Update vgetent in vpopmail.c to properly read old vpasswd files 
           without a cleartext password field.

3/18/03  "Ken Jones" kbo at inter7 dot com
         - add --enable-rebuild-tcpserver-file option, default yes
           turning it off will stop tcprules from being run 
         - add display during configure if ldap is selected
         - add --enable-active-directory option
         - create new vauth_crypt() function to use instead of crypt directly
           this is needed since active directory is so brain dead
         - remove pw_comp() function and use new vauth_crypt function.
           
5.3.19
3/5/03   "Bill Shupp" hostmaster at shupp dot org
         - Updated DOMAIN QUOTAS section in README.quotas
         - added --enable-domainquotas configure option.  Default is off.
         - added newline to the end of vpopmail.config.sh so that it's usable
3/2/03   "Anders Brander anders at brander dot dk"
         - Do not report "failure to open limits file" to syslog
2/26/03  "Brian Kolaci" bk at kola dot com
         - bugfix - increase the SQL buffer size to 2K rather than 600 bytes
           in vmysql.c
         - updates to maildirquota.c so that it can now be compiled into
           libvpopmail without clashing with courier declarations.


5.3.18
2/20/03  "Bill Shupp" hostmaster at shupp dot org
         - Added DOMAIN QUOTAS section to README.quotas
         - Fixed vget_limits() problem with loading from .qmailadmin-limits 
2/20/03  "Brian Kolaci" bk at kola dot com
         - added non-system domain quotas to vdelivermail with these 2 
           functions:
         - int readdomainquota(const char *dir, long *sizep, int *cntp);
         - int readuserquota(const char* dir, long *sizep, int *cntp);


5.3.17
2/20/03  "Andrew Kohlsmith" akohlsmith-vpopmail at benshaw dot com
         - Updates to the PostgreSQL module

2/20/03  "Bill Shupp" hostmaster at shupp dot org
         - vpopbull now terminates if '-f [email_file]' is omitted
         - vpopbull now checks that email_file is not empty
         - vpopbull now reports domains given on the command line that do not 
           exist, but does not exit
2/17/03  "Bill Shupp" hostmaster at shupp dot org
         - Fixed vset_lastauth bug in vcdb.c that didn't check the return of 
           vauth_getpw.  This caused vadduser -s to coredump.
2/10/03  "Ken Jones" kbo at inter7 dot com
         - New oracle module


5.3.16
1/27/03  "Brian Kolaci" bk at kola dot com
         - Performance improvement to vopen_smtp_relay() - now tcprules is
           only run if a new IP is added to the relay table.  This applies
           to sql authentication modules, as cdb already had this feature.


5.3.15
1/25/03  "Bill Shupp" hostmaster at shupp dot org
         - Added ifdefs to vdeloldusers so it will compile with
         --enable-auth-logging=n
1/23/03  "Brian Kolaci" bk at kola dot com
         - Updated vlimits patch


5.3.14
1/13/03  "Michael Bowe" mbowe at pipeline dot com dot au
         - fix for --enable-mysql-logging being too verbose


5.3.13
1/13/03  "Bill Shupp" hostmaster at shupp dot org
         - major changes to vdeloldusers
         - Works with any module that supports auth-logging (mysql, cdb)
         - lots of cleanup.. removed all mysql specific code
         - deprecated -r switch, replaced it with -V (verbose)
         - users are NOT deleted by default.. a new -D argument is 
           required to actually delete users
         - brought back the -d option to specify only one domain


5.3.12
12/7/02  "Bill Shupp" hostmaster at shupp dot org
         - Minor changes to vlimits.c so that it will compile, but more
           effort is needed to implement Brian's new structure
12/6/02  "Jens Jahr" Jens dot Jahr at novasoft dot de
         - Various LDAP fixes
11/20/02 "Brian Kolaci" bk at kola com
         - Updated vlimits structure
10/31/02 "Bill Shupp" hostmaster at shupp dot org
         - Changed valias_line to be type "text" instead of "blob"

10/25/02 Justin Heesemann jh at ionium dot org
         - Minor fix for users-big-dir

10/24/02 "Bill Shupp" hostmaster at shupp dot org
         - fix for vipmap so that usage() is displayed if no arguments are 
           given
         - TCPLOCALIP is in IPv6 format from couriertcpd.  Convert to IPv4 
           in host_in_locals() so that ip-alias works with courier-imap

5.3.11
10/23/02 "Bill Shupp" hostmaster at shupp dot org
         - Forgot to change defualtquota type in limits structure

10/23/02 "Pablo Murillo" pm at rednet dot com dot ar
         - Fix for Delivered-To header getting mangled if you used a 
           different DOMAINS_DIR.

5.3.10
10/23/02 "Bill Shupp" hostmaster at shupp dot org
         - Added limits table layout to vmysql.h
         - Changed valias_line to be type "blob" to compensate for large
           mailing list commands.  Increased FILE_LINE_SIZE to 1024 in 
           vcalias for the same reason.  vcalias now escapes FileLine input.
           Thanks to Brad Dameron for pointing this out.
         - Added disable_smtp support to the new vlimits functions
         - Fixed configure.in so that --enable-mysql-limits is now reported
           after running configure
         - Moved format_maildirquota() to the vpopmail library.  Updated 
           vlimits.c to use format_maildirquota() for default_quota.
         - format_maildirquota() now uses 1024 and and 1048576 when 
           converting KB and MB instead of 1000 and 1000000, respectively.

10/23/02 "Anders Brander" anders at brander dot dk
         - vdelivermail: Check for | *before* /Maildir/ in .qmail processing
         - vdelivermail: Add missing case for error code 100

5.3.9
10/21/02 "Bill Shupp" hostmaster at shupp dot org
         - Add error checking to vpopbull so that if copy_email fails,
           report it on the command line.
         - Update admin guide to reflect new limits functions

10/21/02 "Edoardo Serra"  vpopml at connecting dot to dot it
         - automatically create maildir in vpopbull if it doesn't exist

10/18/02 "Bill Shupp" hostmaster at shupp dot org
         - Added wildcard support (i.e listname-default) to vdelivermail's
           process_valias function.  Should allow ezmlm lists to be run
           from the valias table.

10/17/02 "Brian Kolaci" bk at kola dot com
         - Added 3 new api functions to administer .qmailadmin-limits:
              int vget_limits( char *domain, struct vlimits *limits )
              int vset_limits( char *domain, struct vlimits *limits )
              int vdel_limits( char *domain )

10/16/02 "Bill Shupp" hostmaster at shupp dot org
         - Fixed typo in vcalias.c

09/11/02 Dave Boodman dave at boodman dot com
         - vdelivermail missing case for exit code 99 when exec'ing
           users .qmail programs. Needed for processing of autorepsond
           result codes of 99

09/05/02 "Steve Fulton" steve at esoteric dot ca
         - vdelivermail now handles error return codes 100 and 99
           when processing users .qmail files. Support for autoresponder
           exiting with 99. 

5.3.8
07/16/02 "Bill Shupp" hostmaster at shupp dot org
         - one last patch for the vgetent problem
         - comment out lseek definition for bsd users
         - Replaced old qmail-pop3d-maildirquota patch with 
           qmail-maildir++.patch.  This one adds Maildir++ support not only 
           to qmail-pop3d, but also to qmail-local.  Updated documentation 
           to reflect this.  This one is closer to Sam's original code, too.

07/10/02 "Boris Manojlovic" steki at verat dot net
         - CLEAR_PASS ifdefs in vpopmail.c

5.3.7
06/21/02 "Bill Shupp" hostmaster at shupp dot org
         - add --enable-make-seekable option (default y) so that people can
           turn off the seek patch if they want
         - relplace MIN with vmin(int x, int y) in seek.c for better 
           portability (thanks to Ken Jones)
         - Change exit codes to 1 instead of 0 for NO_POP and NO_SMTP 
           restrictions.  Thanks to Michael Bowe for pointing this out.

06/20/02   "Maurice Snellen" maurice at hypercube dot demon dot nl
         - replace inappropriate strcmp test when for checking LocalPort in
           vchkpw.c

06/12/02   "Paul Kremer" pkremer at dullboy dot gms dot lu
         - set ldap protocol version before each ldap_simple_bind_s call.
           Default version is 3, but you can change it in vldap.h.

06/04/02  "Justin Heesemann" jh at ionium dot org
         --enable-users-big-dir option.  On by default, this allows you to 
           turn off using big dirs for users (and allow 1 char account names)

05/17/02   "Rui Barreiros" rui at websolut dot net
         - fix aliased domain problems

12/13/01   "Marcus Williams" marcus at quintic.co.uk
         - seek patch.  Original code by University of Maryland Computer 
           Science Department.

5.3.6
05/18/02   "Bill Shupp" hostmaster at shupp dot org
         - New APOP code for vchkpw.  Relies on clear passwords to work.
         - APOP arguments removed from vadduser, vpasswd, and vadddomain since
           the new APOP code doesn't need them.  (still need to remove old APOP 
           code, update API)
         - Added CRAM-MD5 support for SMTP-AUTH only.  Requires clear passwords
           and the smtp-auth patch (for qmail-smtpd) from:
           http://members.elysium.pl/brush/qmail-smtpd-auth/
         - Authentication type is now logged upon successful authentications
         - Removed logging of *correct* passwords
         - Fixed vgetent() problem that should clear up the clear/crypted
           password problems in the cdb module.
         - Added NO_SMTP gid flag and support for it in vchkpw, vmoduser, and 
           vuserinfo
         - Fixed lots of bugs in vpopbull.  The old -v switch is now -V 
          (verbose) and now -v is the version argument (for compatibility)
         - qcalc() fix for incorrect quota percentages with large quotas
         - vdelivermail now checks the EXITCODE of a forked process
         - updated TODO


5.3.5
04/16/02 - tab character replaced by 4 spaces in open-smtp file broke
           roamin-users feature
         - vchkpw syntax error when checking if roaming-users should be
           called based on the incoming portnumber.


04/03/02   Tim at timtasi dot com
         - much better parse_email function [774404]

5.3.4
04/02/02 - Doh! syntax error in vmysql.c, fixed

04/01/02   Matt Wierdl Dept of Math. Sciences University of Memphis
         - If we can not get a lock file on updating a file return an error

         - vget_assign: strncpy into in_domain malloc'ed memory instead
           of into incoming domain variable.

03/28/02 - vmysql.c: remove malloc in vauth_pw and use static local var

03/27/02 - code review and indent updating of vpopmail.c
         - more cleanup of parse_email function. it is still nasty looking

03/25/02   Tim tim at timtsai dot com
         - parse_email not terminating the user with a null in the right spot

03/20/02 - clean up indentation in vchkpw.c
         - enable-logging=v was not logging successes with passwords

03/18/02   Andrey Chichmeli az at primorsky dot ru 
         - vpopmail.c: use MAX_PW_GECOS to check pw_gecos string

03/15/02 - domains must be at least 3 characters long: a.b

03/13/02 - new version
          
           "Joe Ingersoll" jingersoll at geektech dot com
         - vconvert.c -e -m needed pw_passwd+1 instead of pw_name+1

5.3.3
03/12/02 - relay control: read in tcp.smtp before the open smtp lines
           that way the tcp.smtp file will take precedence 

02/24/02   Antonio Nati" tonix at interazioni dot it
         - syntax error in vcdb.c git_t should be gid_t

02/23/02 - blank password fields would cause cdb module to not
           return all users.
         - --enable-ldap=y was not setting the lib_dep file correctly

02/22/02   Nelson admin at typhoon dot jp
         - more changes to postgresql modules. Now vadddomain, vadduser
           vdeldomain and vdeluser work.
         - new README.pgsql

           Tyler gtyler at onestop dot net
         - addition to FAQ file for runnin vadddomain or vdeldomain as
           non root user (vpopmail in our case).

02/20/02   Nelson admin at typhoon dot jp
         - vmysql.c duplicate vauth_open_read in vshow_ip_map  removed
         - port vmysql.c to vpgsql.c
           We now have a beta upgraded PostgreSQL file!

02/19/02 - update README.mysql to be current, it was saying to use
           --enable-sqlincdir and --enable-sqllibdir. It should say
           --enable-incdir and --enable-libdir
         - restrict access to vauth_getpw function to only root
           or the user who owns the domain.

5.3.2
02/19/02 - add checks and set globals depending on what port the
           connection is coming in on. 
         - set the syslog message string based on what port the
           connection is coming in on.
         - For smtp authentication connections no need to setuid,
           setgid or change directory.

02/18/02 - change vchkpw.c message when people run on the command line.

02/17/02   "Maxim Krikuha" <maxim@sibtel.ru>
         - update vdelivermail.c to support .no-user.msg file in
           either the domains directory or under the vpopmail home
           domains directory.

5.3.1
02/13/02 - code review of virtual and system users authentication 
           with vchkpw.c 

02/12/02  "Brad Dameron" <bdameron@tscnet.com>
         - typo in vcalias.c file fixed

          "Bill Shupp" <hostmaster@shupp.org>
         - update vchkpw.c if thelocal port is 25 or 465 then
           do not open a relay and 
           use vchkpw-smtp or vchkpw-smtps in the logs
 
02/11/02 - mysql section was ignoring --enable-libdir and --enable-incdir
           if /usr/local/mysql exists

02/09/02 - remove redundant permission settings in Makefile.am for 
           make install on the bin and lib directories

02/05/02 - vpopmail.h increase MAX_PW_QUOTA  to 20 to support Maildir++
         - vconvert.c parse assign file instead of walking the
           vpopmail/domains directory to find all domains

02/04/02 - change permisisons on vpopmail/bin to only allow
           root and vpopmail users to access it. This combined
           with the permissions on the lib directory for mysql
           sites secure the compiled in password from user detection.
         - remove root setting on lib directory. Allow root and vpopmail
           access to the libraries.

5.2.1
05/18/02   "Bill Shupp" <hostmaster@shupp.org>
         - Back ported these fixes from 5.3.6 for an interim stable release:
            - vgetent() fix
            - vpopbull fixes
            - qcalc() fix for quota percentages
            - EXITCODE checking for vdelivermail

5.2
02/01/02   "Michael Bowe" <mbowe@pipeline.com.au>
         - increase the mysql pw_shell (quota) field from 12 to 20 chars.
         - vmysql_escape was not applying the terminating NULL char and
           hence could contain additional strings from prior calls.
         - look for quotawarn message in both the virtual domain directory
           for the domain and if that fails look in vpopmail dir
         - look for user over quota message file in both the virtual
           domain directory and if that fails look in the vpopmail dir 

           "Donal Diamond" <donal.diamond@eircom.net>
         - typo on putenv in vchkpw.c for HOME
       
         - name field displayed twice in vuserinfo

01/31/02 - 5.2 stable release
         - update vgetent, wasn't parsing vpasswd files correctly. Used
           in vcdb.c vauth_getall() function.

           Michael Bowe <mbowe@pipeline.com.au>
         - update vdelivermail to populate TheDomainDir from vget_assign
           fixes problem with quota warn messages
            
           Donal Diamond <donal.diamond@eircom.net>
         - vdelivermail.c if bounce address is an email address and
           it is local, just delivery it without needing to re-inject

5.1.11
01/30/02 - put back in get_real_domain in vdelivermail.c for backwards
           compatibility for all alias domains

01/29/02 - line 497 in maildirquota.c cast const char * as char *
           for warning: assignment discards qualifiers from pointer

01/28/02 - created vaddaliasdomain function in vpopmail.c
         - added valid character check to vaddaliasdomain() function
         - updated vaddaliasdomain.c to call new vaddaliasdomain() function

5.1.10
01/26/02 - finally got the alias domains straightened out. Changed
           the format of the assign file. It now contains:
            +aliasdomain-:real_domain:uid:gid:path_to_real_domain:-::
           So a real domain would look like
            +test.com-:test.com:89:89:/home/vpopmail/domains/test.com:-::
           and an alias domain would look like
            +ken.org-:test.com:89:89:/home/vpopmail/domains/test.com:-::

         - del_domain_assign and add_domain_assign now take both of the
           domain entires for the above line.
      
         - vget_assign now will over write the incoming domain name with
           the real domain name. So from the example above, if you call
           strcpy( domain, "ken.com");
           vget_assign(domain, dir, uid, gid); The domain variable will
           contain "test.com".

         - the end result is that email can be delivered to aliased domains
           and users can authenticate as aliased domain users.

         - removed the need for vget_real_domain() function

           Casey Zacek<cz@neospire.net>
         - got the mysql alias code "a changin'"
           

01/25/02 - no need to create symbolic link for aliased domains
         - modify vauth_getpw in vmysql.c to get real domain name
           for aliased domains
 
01/24/02   Casey Zacek <cz@neospire.net>
         - vmysql.c had a typo (missing comma) in vcreate_dir_control().  
            Added identifiers to all the vmysql error messages.
  
5.1.9
01/24/02   Boris Manojlovic <steki@verat.net>
         - for MD5 passwords in vpopmail.c mkpasswd3() routine
           use more than 2 random chars in salt

         - vldap.c support MD5 passwords

01/23/02   Boris Manojlovic <steki@verat.net>
         - New ldap code and ldap directory with ldap files

           Eric Peters <eric@peters.org>
         - "domains" directory is now configurable in configure script.
           He wanted to be able to change the name of that directory
           when he placed users email's under an /etc/passwd users home
           directory. 

         - break out of infinite sleep in maildirquota.c when
           trying to safely open a file (file locking)
 
         - missed a TheUserExit typo in vdelivermail.c, fixed

01/22/02 - add support for MD5 encryption of passwords with
           new --enable-md5-passwords=y configure option. 
           The default is yes

01/19/02 - vdelivermail.c: code review
         - vdelivermail.c: standardize code indentation
         - vdelivermail.c: Add TheDomainDir TheDomainUid TheDomainGid
             set them at initialization time with vget_assign
         - Use TheDomainDir for formatting file name for quota messages
           works with hashed domains

         - --enable-file-sync=n is now default. Not really needed 

         - vdelivermail.c: check_forward_deliver does a chdir so that
             any .qmail file Maildir lines will support relative paths
         - vdelivermail.c: Support any full or relative path for Maildir
           deliveries
         - vdelivermail.c: if moving (link/unlink) a file from the tmp
           dir to the new dir (Maildir) fails, delete the failed file 
         - vdelivermail.c: found that duplicates of an email delivered
           to a user on the same invocation of vdelivermail will fail
           (Maildir processing) because the file name will be the same

01/18/02 - if .qmail file contained a &email_address line then
           free in qmail_inject vfork function would free wrong address

         Vladimir Kabanov <vladimir.kabanov@vvsu.ru>
         - add support for ./Maildir/ inside users .qmail file
           in vdelivermail.c deliver_mail() function

 
01/17/02   Albert Hopkins <ahopkins@dynacare.com>
         - typo in vpopbull.c needs to look at /var/qmail/users/assign

         Richard A. Secor <rsecor@seqlogic.com>
         - vlog support version 0.22
         - new vlog readme

           Bill Shupp <hostmaster@shupp.org>
         - new README.quotas
         - new FAQ entry for pop3d
         - include pop3d maildirquota patch in contrib dir

01/16/02 - Add Richard Secor's vlog support version 2.0 to contrib dir
         - vuserinfo, if user never logged in display account creation time
         - one more try with setting Delivered-To header for email
           that is delivered to the catch all account. In that one particular
           case we set the Delivered-To header to be the user@domain of
           the incoming email address.

5.1.7
01/14/02 - configure now checks if person didn't read the configure options
           and put in the path to the directory that contains programs 
           instead of the full path to the actual program. This is for
           qmail-newu, qmail-newmrh, qmail-inject, tcprules
         - get rid of long jump clobbered warning message
         - get rid of not exiting with a return thingy warning messages

01/13/02 - no need to create the ~vpopmail/users directory since it
           is no longer supported recommended for use.

01/11/02 - vgetent - remove the check for number of fields, this should
           allow clearpassword and non clearpasswd files to be read
         - redo vmake_maildir to take domain and user dir to create
         - update vchkpw to autocreate users maildir if it is missing
         - update vdelivermail to autocreate users maildir if it is missing
         - add new is_username_valid(char *user) function
         - add new is_domain_valid(char *domain) function
         - updated everything to use new validation characters

         Chris <chris@ms.black-oak.com>
         - chris got us going on checking all valid chars in an email address
   
         - update mysql module to always use " character instead of
           ' character for placing around strings

5.1.6
01/09/02 - vset_lastauthtime was a bad idea, removed
         - when a user is created, set thier last auth time to
           the current time, and their IP to 0.0.0.0

01/08/02 - change default of --enable-clear-passwd to be no
           two reasons, 1) will break current installs
           2) people should make an effort to store clear passwords
         - vpopbull using wrong directory path to assign file.

01/05/02 - add usage for -r to vdeloldusers  Jason Kerr
         - update vmysql.c module to escape gecos, pass and clear pass 
           fields before inserting into the database.
         - in vchkpw, if invalid email characters are passed as user@domain 
           then syslog an error and exit
         - in vcdb module, don't allow ":" character in gecos field or
           in clear text password field. They are both kind of a hack.
           The fix just strips the ":" character out of the field.

5.1.5 
01/05/02 - change --enable-hardquota to --enable-defaultquota
         - add vvalidchar(char *) function to check if character is 
           a valid email character set new VA_INVALID_EMAIL_CHAR verror
           global on invalid character
           The valid set of characters is:
              a to z
              A to Z
              0 to 0
              . - and _
 
         - update vdelivermail to use vvalidchar when getting user/domain
         - update parse_email to return error code if invalid character
         - update valias command to use Alias buffer instead of User buffer 
         - update vpalias.c valias_insert to check for "." in .qmail file name
         - add -r option to vdeloldusers to just report old users, not delete
         - if mysql enabled and lastauth table not yet created then 
           vdeldomain would not delete valias entries for the domain, fixed
         - lastauth entry not created when user is created
         - add vset_lastauth_time() function
         - updated vcdb.c vmysql.c vldap.c to support vset_lastauth_time()
         - lastauth was not seting the ownership of the lastauth file
           to the owner of the domain for the cdb and ldap modules, fixed
         - update vconvert to be able to convert from cdb or /etc/passwd 
           to the compiled in module, cdb/sql/ldap or what ever was compiled
           into vpopmail.

01/02/02 - change caddr_t to (char *) in maildirquota.c
         - vpopbull gets domain directories from assign file now
         - vdeloldusers requires -e option to run 

12/29/01 "Jason Kerr" <jasonk@shaw.ca> suggestions
         - vadduser not set the last authentication time
         - vuserinfo report "never logged in" instead of 
           unix time 0 Wed Dec 31 18:00:00 1969
         - add new vget_lastauthip() to return IP of client's last connection
           added it to the vcdb.c and vmysql.c modules
         - vdeloldusers() don't delete postmaster account
         - remove unused -d domain option from vdeloldusers
         - --enable-clear-passwd=y is now the default



12/27/01 "Yuri A. Kabaenkov" <sec@artofit.com>
         - add -r option to vadddomain and vadduser to generate a 
           random password.

         - add new vpopmail API function to generate a random password
             char *vgen_pass(int len). returns a pointer to malloc'ed
             memory filled with a random password of size = len.
         - small typo in maildirquota.c fixed
         - update maildirquota.c to use snprintf() instead of sprintf

5.1.3 and 5.1.4
12/26/01 - vpopmail.c signal_process() does not kill itself
         - added vkill program to kill any running process that contains
           the string passed on the command line. killall won't do that.
           example: vkill qmail- will kill all qmail processes including
            any tcpservers running qmail, but not tcpservers running 
            other things.
         - vdeldomain now checks if the directory is a symbolic link
           and then only removes the link

         "Bill Shupp" <hostmaster@shupp.org>
         - Fixed typo that prevented accounting of quota warning messages
         - Fixes for format_maildirquota() and how it's called.
         - Messages < 1K are no longer delivered after user has exceeded 
           their quota. There's no need for this since we have proper 
           warning messages now.

         "Richard A. Secor" <rsecor@seqlogic.com>
         - change the timestamp in vlog to a UNIX Timestamp.


12/24/01 "Bill Shupp" <hostmaster@shupp.org>
         - vaddaliasdomain, get dir from assign file instead of
           assuming it's under ~vpopmail/domains. 

12/20/01 "Bill Shupp" <hostmaster@shupp.org>
         - moved quota conversion code into format_maildirquota()
         - warning messages are now accounted for in quota
         - warnings are still delivered even if the user is over quota
         - fixed unformatted quota bug in vmoduser -Q

         Donal Diamond <donal.diamond@eircom.net>
         - if the mysql server is down, deffer valias deliveries

         - new configure default
           --enable-auth-logging=y 
         - wrong MAX_PW fields checked in a few functions
         - MAX_ALIAS_LINE redefined in vpalias.c
 
12/19/01 - set max field sizes in vpopmail.h
         - update mysql to use fixed field sizes
         - error checks for field size limits in all functions
         - vpopmail.h header changed to not say util.h

12/18/01 "Nicholas L. Nigay" <nnigay@cboss.ru>
         - Fix for "qmaildir" path being hardcoded in configure.in
         - Fix for incorrect file size in quota warning message file name
 

5.1.2      
12/18/01
         - update MAX_BUFF in vpopmail.c to support maximum sized
           domain names.
         - change #ifdef in vchkpw to #ifdef HAS_SHADOW instead of
           #ifdef HAVE_SHADOW_H

12/17/01
         - added report for VA_BAD_CHAR to verror
         - fixed error check for bad character in gecos field in 
           vadduser API.
         - add check for length of domain name

12/15/01
           Hendry D Lee <hdlee@jetcoms.net> and Mike Rogers
         - if clear passwd is empty and learn passwords is on 
           then set the password

5.1.1
12/10/01   Bill Shupp <hostmaster@shupp.org>
         - Added quota warning messages
         - added -Q option to vuserinfo to display current quota usage
12/04/01 - switch from old quota system to Mr. Sam's maildirquota system.
            See README.quotas for more information.

5.1.0    - update version
12/03/01

5.0.1
12/03/01   Bill Shupp <hostmaster@shupp.org>
         - usernotfound() fix for non vpopmail user domains - catchalls
           would bounce.  Yavuz Aydin pointed this out.
         - vegetent() fix (cdb module) vmoduser would corrupt the vpasswd
           file when running on an entire domain.
         - vmoduser wouldn't set the passwd field when running on entire
           domain
         - re-added .over-quota.msg support to vdelivermail

11/24/01 - kbo@inter7.com
           changed the vchkpw error message about fd 3 when
           people try to run it on the command line. Try it.

5.0
10/23/01 - valias -s domain with mysql would core dump. 
           tracked it down to vget_real_domain calling
           vget_assign returning NULL but not checking.

         - Bill Shupp
           update vconvert usage() message

10/22/01 - update vconvert to work correct from cdb to mysql
         - open relay template file name was wacky, fixed.
         - unlink of empty template file was bad, fixed.

10/17/01 - Arthur Mills <aem@fiberpipe.com>
           login_system_user() in vchkpw.c should use vchkpw_exit(X)
           where X is not 0 for invalid logins. Fixed.

10/11/01 - add #ifdef around open_smtp_relay in vchkpw.c because
           some compilers are stupid.

         - vchkpw.c for shadow /etc/passwd systems was using TheName
           instead of TheUser. This would not break anything but
           it is changed to be consistant.

         - solaris compilers get -R$libdir

10/04/01 - Vladimir Kabanov <vova@farpost.com>
           vdelivermail.c had incorrect Delivered-To: header
           for users in sub directories fixed.

10/01/01 - Found by: Pontus Hanserkers <pontus@e-Pontus.com>
           vcdb.c vsetuserquota incompatible with clear passwords.
           vcdb.c vauth_setquota() now calls vauth_getpw() then 
           vauth_setpw() to do the underlying changes of the users 
           information, quota.

         - Bill Shupp 
           updates to vuserinfo.c and vmoduser.c for qmailadmin
           administrator privilages pw_gid bitwise flag QA_ADMIN

09/26/01 - change MYSQL_PORT to MYSQL_VPORT. Mysql include file already
           has MYSQL_PORT
 
09/25/01 - add #ifdef for POP_FETCH lib
         - delete tcprules temp file in case tcprules has an error
         - system users were not able to pop auth relay, fixed
         - add new QA_ADMIN flag for qmailadmin

09/18/01 - add sys/varargs.h check in configure.in
           update vpopmail.c to have #ifdef around sys/varargs.h
           which is needed for solaris 8 machines

09/17/01   
           Steve Wolfe <nw@codon.com>
         - with --enable-password=y vchkpw.c:397: undefined reference to 'log'
           looks like the line should actually use vlog(), not log().


           Marcus Williams <marcus@quintic.co.uk>
         - vdelivermail.c lseek calls had a few with SEEK_SET in 
           the wrong order. 

5.0pre6
09/15/01   Jan Pavlík <gandie@rootshell.cz>
         - Hi, i think there is 5 or 6 real_connects but you set 
           MYSQL_PORT for 2 only...

09/12/01 - update vdelivermail to use qmail's DTLINE environment
           variable to set the DeliveredTo address when vdelivermail
           delivers email to a catchall account. 

         - Jan Pavlík <gandie@rootshell.cz>
           add #define MYSQL_PORT 0 to vmysql.h in case folks
           want to hard code the port number. The default of
           0 lets mysql read my.cnf files to set the port number.

         - configure now says that --enable-passwd=n is the default.
           It was the default already, now it just says it.
          
5.0pre5  
09/07/01 - vmysql.c now checks for database fields being NULL
           and properly handles it. No crash on NULL fields

         - update the parse_email() function to also automatically
           check for alias domains. This function is used in the
           vchkpw auth program. So now, users can authenticate
           against a domain or any of it's aliases. It uses
           the vget_real_domain() function to change the domain
           from an alias to the real one.
           
5.0pre4 
09/06/01 - if mysql server is down email delivery is deffered 
           instead of bounced.

         - auto creation of maildir on email delivery in vdelivermail
           now works. Wasn't added in when the vdelivermail was
           completely re-written.

         - Einar Bordewich <einar-qmailtools-vchkpw@bordewich.net>
           when adding a new user, if the directory already exists
           do not delete it and add it again.  This was a feature
           but turns out it can delete mailing lists.

5.0pre3
09/06/01   Pascal Lauly <pascal@planet-service.com>
         - reported bug with cdb module, adding a user with
           the name of "vpasswd" trods on the vpasswd file
           fixed in vcdb.c

5.0pre2
09/05/01 - vadduser -n option now sets the password to blank so
           it can be used with --enable-learn-password=y

         - add --enable-learn-passwords configure option.

5.0pre1
09/04/01 - first 5.0 release canidate

4.10.36
09/04/01 - include vchkpw "learn password" feature.

08/30/01 - configure creates a vpopmail.config file with the command
           line needed to re-run configure with all the selected options

08/29/01 - vcdb module, update vauth_getall to support 
           clear text passwords and blank fields

4.10.35  
08/20/01 - security permission change on lib directory and library
         - vauth_user now will set blank passwords first time.
         - blank passwords are set in vchkpw too

4.10.34
08/16/01 - vol@inter7.com
           new vldap.c module

4.10.33
08/08/01 - David Wartell <david@actionwebservices.com>
	   fix qmail-ext to process -ext like qmail.
         - David Wartell <david@actionwebservices.com>
           add mysql logging.

4.10.32
08/05/01 - added -e "encrypted passwd" to vadduser.
         - remove APOP from vadduser

08/04/01 - JM Roth <jm@roth.lu>
           configure --help for --enable-sqwebmail-pass did not
           make sense. updated it.

08/02/01 - "Richard T. Wareing" <rwareing@requestnetworks.com>
           vmysql getall function returning incorrect gecos field
4.10.30
07/30/01 - finally update vconvert for removal of large/small site
           api's in the vmysql.c module. Now it will run.

07/19/01 - vcdb.c needed address to memset
         - tested smtp authentication - Works!
         - vcdb module return a null string instead of 0 for clear_passwd

07/12/01 - updated vchkpw.c to use <sys/wait.h> instead of <wait.h>


4.10.29
07/12/01 - filter out supervise on signal kill 

07/11/01 - vpopmail.c: decrement dir control was using "master_domain"
           instead of dom_"uid". fixed

         - vpopmail.c: check for domain existance before doing anything else 
           in api vadddomain()

         - vmoduser.c -q Quota was not updating quota

07/07/01 - vmysql and vcdb modules, set the pw_clear_passwd field
           to NULL in vauth_getpw calls. Just so we know the 
           vpw->pw_clear_passwd field doesn't contain a garbage
           pointer

         - removed the vdelivermail message about delivering the email
           to a different user.

07/06/01 - vadddomain had "vaddomain" in the help text

4.10.28  
07/06/01 - vdelivermail checks the DTLINE to see if mail is looping

         - qmail_inject reading from fd 0 doesn't allow for setting
           a delivered to line. So back to the old way of writing it.

         - getall mysql select was wrong, was fixed, crept back into
           the source. fixed

07/03/01 - if the users directory exists, delete it and keep going
 
4.10.27
07/03/01 - "David Wartell" <david@actionwebservices.com>
           Solaris and Linux have different results with unlink()'ing
           a directory. Linux returns and error and Solaris doesn't.
           David's code checks handles this and correctly works with
           both solaris and linux (presumably with other OSen).

         - "Chris Bunnell" <cbunnell@sonicisp.net>
           reverse the check in vdelivermail for user over quota.
           messages of less than 1000 bytes were not updating the
           .current_size file. 

07/01/01 - "Robin S. Socha" OpenBSD 2.8 wanted #include <signal.h>
           in vdelivermail.c, now that vdelivermail is looking
           at signals.

         - updated all the vchkpw exit codes to be non-zero in
           case of any errors. It only returns 0 if successful
           authentication takes place.

4.10.26
06/29/01 - in vdelivermail figured out how to share the standard in
           file descriptor with qmail-inject and any programs that
           get exec'd. That way programs can rewind thier input and
           we save read/writing the whole message through memory.

4.10.25
06/29/01 - "Alex Hathaway" <alexh@synapseglobal.com>
           configure option for solaris 2.8 for finding the id command.

06/28/01 - vdelivermail used a small buffer of 100 to handle .qmail
           file deliveries in a users directory. This is not large enough

06/27/01 - noticed there is no end function for getall, added 
           vauth_end_getall(), helpful for mysql aborted connections.

         - stupid vmysql.c vauth_getall wasn't filling in the clear
           password field and the ifdef had the wrong word

06/26/01 - "chris" <macgyver@sonicisp.net>
           - After much debugging work Chris found in vadddomain it 
             lower cases the directory. This breaks directories that
             have upper cases in them, like /RAID
           - update to configure script to set shared object library path

         - updated all vmysql.c mysql_result calls to call mysql_error
           on an error. 

4.10.24
06/25/01 - Programs which did not call vclose(), vdominfo, vaddaliasdomain,

         - vadddomain was using the old domain directory structure
           (no hashing) to check for a domains existence. So it was
           not successfully finding existing domains. It now calls
           vget_assign to check if the domain exists in the assign file

         - configure now checks for the location of qmail-inject, 
           qmail-newu and qmail-newmrh for distributions (prolly Debian)
           which put them in different locations.

         - Daniel Savard <daniel.savard@gespro.com>
           fixes to vcdb.c in vread_dir_control to start index loop
           at 0 instead of 1, i=0. 

4.10.23
06/23/01 - update configure to check for location of qmail-newu
           Debian decided to move it into /usr/sbin. By the way,
           Debian's policies on open source software are keeping
           qmail and any program that uses qmail, off zdnet/appwatch
           software download site. 
           - thanks to Patrick Earl <patearl@patearl.net> for
             clearly pointing out the differences in Debian.

         - vauth_getall in mysql module had wrong number of columns
           for the many domains option

         - vuserinfo was not displaying all the fields

         - vcdb module bug which caused a new line to be in the path
           to a domain. caused assign file to be corrupted and a wierd
           file named "?" to be created in /home/vpopmail/domains
           All fixed
 
4.10.22
06/21/01 - Daniel Savard <daniel.savard@gespro.com>
           change to vpopmail.c vgetent function for CLEAR_PASS

         - Rick Stanley <sysadmin@rsi-ny.com>
           fix for Delviered-To: /path/to/maildir. Now it correctly
           states the accounts *real* email address.

06/18/01 - "Tim Hasson" <tim@aidasystems.com>
           README.ldap documentation and testing

         - OptimizeNewDomain will now compile users/assign file.

         - signal_process will signal any process which contains
           the process name

4.10.21
06/16/01 - remove use of fscanf in vcdb.c module so vpopmail/cdb 
           can be compiled with dietlibc  

         - removed the filter option in configure and the README.filter
           file from the distribution. The same functionality can
           now be done with maildrop.

4.10.20
06/13/01 - end of configure script uses IP_ALIAS instead of IPALIAS

         - vshow_ip_map in vmysql.c would fail if the ip_alias_map 
           table was not created first.

         - updated the copy write notice for year 2001 in all files

         - "Marcus Williams" <marcus@quintic.co.uk>
            temporary version of open_command for vdelivermail

         - Antonio Dias <accdias@sst.com.br>
           compilers complain if vdelivermail.c doesn't end with an exit()
 
4.10.19
06/13/01 - added vchkpw_exit() function to vchkpw to do vclose()
           and closelog(). 

         - added --enable-file-sync=y (default) or no
           no will stop vdelivermail from calling fsync/fdatasync 
           when it delivers mail.

         - Antonio Dias <accdias@sst.com.br>
           vset_lastauth in vcdb.c wasn't returning a value when 
           auth logging is enabled.

         - clean up vmysql.h and vmysql.c

         - clean up command line processing skeleton code in vdelivermail

         - add a vdl_exit() to call vclose in vdelivermail

06/12/01 - more ifdefs in vmysql.c and vmysql.h to clean up
           sql queries

         - no more need for xyz_size functions in vmysql.c

         - changed --enable-large-site=y to --enable-many-domains=n
           and --enable-large-site=n becomes --enable-many-domains=y
           Hopefully, this will be less confusing in the future.

         - finally take the big plunge and change all sprintf's to
           snprintf's. Any OS's that don't have snprintf should 
           install it.

4.10.18
06/11/01 - yet another fix to vget_assign for cdb module. It was
           doing a strncpy from a NULL pointer, that's bad. 

         - error in vaddaliasdomain created the incorrect directory
           in /var/qmail/users/assign, fixed.

         - Ryan Duda <rpd@123.net>
           - put in vclose before exits in vchkpw.c and vdelivermail.c
           - vchkpw wasn't getting the pw_uid and pw_gid 

         - Antonio Dias <accdias@sst.com.br>
           - another switch in vcdb.c from strncpy to strncat
           - vpw instead of pw in vcdb.c vset_lastauth()
           
06/10/01 - Antonio Dias <accdias@sst.com.br>
           fix for file locking ifdefs in file_lock.c
           fix for vcdb.c dc_filename to use strncat not strncpy

         - error in vchkpw.c calling vset_lastauth with the wrong
           first parameter

         - found one more %ul instead of %lu in vpopmail.c

         - more type casting of pid_t and off_t to unsigned long
           to make freebsd happy

         - configure now checks for fdatasync

         - vdelivermail.c has ifdef for fdatasync. If the function
           is not avaialble it uses fsync instead.
 

4.10.17
06/08/01 - Stupid configure.in file. Was using $vpopmaildir variable
           before setting it. Fixed! Still working forward to the
           5.0 production release. 

         - AddDomainOptimize = 1 now does not compile the assign file
           this vastly increases the speed of bulk domain adds

         - configure now sets FILE_LOCKING = 1 instead of y

         - file_lock.c used FILE_LOCK instead of FILE_LOCKING

         - Marcus Williams" <marcus@quintic.co.uk>
           vdelivermail code review for rename logic, did not
           need to do an unlink if we did a rename.
   

4.10.16
06/07/01 - Marcus Williams" <marcus@quintic.co.uk>
           support for coda file system in vdelivermail in case
           the link() function fails and we have to call rename()

         - code review of vchkpw and syslog calls, check if we
           are logging anything before making calls to syslog.
 
         - Antonio Dias <accdias@sst.com.br>
           fixes to cdb module for dir control processing
           change unsigned long to long unsigned everywhere
           update mysql and postgress modules to use %lu instead
             of %ld for the long unsigned variable

         - update open_bid_dir and vread_dir_control to include 
           the uid and gid fields

         - removed unused read_dir_control and write_dir_control 
           declarations in vauth.h. 

         - vget_assign now correctly handles looking up domains
           that do not exist in the assign file   

         - add a global flag OptimizeAddDomain to turn off compiling cdb
           files and HUP'ing qmail-send

         - fixed a memory leak in mysql vauth_getpw function. If the user
           was not found the mysql result was not released.
        
06/05/01 - Marcus Williams" <marcus@quintic.co.uk>
           optimize vdelivermail Maildir code and sync the file

         - Fix vadduser user for users with no domain

4.10.15
06/04/01 - --enable-passwd=n is now the default. It is slightly
           more restrictive which sounds better for people who
           are trying this for the first time.

         - vdelivermail now properly uses the Maildir/tmp directory
           to write emails to. Then it links it to new and unlinks
           the tmp file.

         - more error checking in vdelivermail write calls. 
           checks for user over quota write failure and returns
           that error so the email should be bounced back.

         - updated vset_lastauth to not require a vauth_getpw first.
           this should speed up vadduser. also with mysql replication
           there can be a race condition with adding the user to
           the master server and it has not shown up on the slave.

         - added a --enable-file-locking option. Default is yes,
           which is backwardly compatible. Some NFS file locking
           implementations are just plain broken out of the box.
           --enable-file-locking=n will avoid that.

4.10.14
06/03/01 - with mysql replication, if we can not connect to the
           read server then try connecting to the udpate server

06/03/01 - modified the vdominfo and vuserinfo programs so that if
           the user specifies to display some of the information,
           the it does not print out a title for each line of 
           information. The idea is that if any program wants
           to get the directory of a user, they can do, 
           ./vuserinfo -d user@domain and it will print out
           the directory followed by a newline. This should be
           easier for programs to parse.

4.10.12
06/03/01 - added a new vdominfo program to display information about 
           one domain or all domains. You can use this to find out
           the directory where the domain is stored. This should help
           out since the domain directories are hashed. It also 
           displays the number of users in the domain.

         - updated vadddomain to support domain directory hashing
           for all users and not just the vpopmail domain users.

         - added new configure option --enable-qmail-ext. This
           was the default in old installations. Now there is
           an option to turn it off.  
           --enable-qmail-ext=y (default) will deliver mail
            for joe-ext@domain.com to joe@domain.com
           --enable-qmail-ext=n will NOT deliver mail for
            joe-ext@domain.com to joe@domain.com. It will
            only deliver it to joe-ext@domain.com

         - added display of ip-alias-domains and qmail-ext to
           the configure print out at the end.

         - updated the vmysql module to use a separate read connection
           for the vauth_getall function. It needs a separate connection
           or else any vpopmail call that is done during a getall
           loop will fail.

         - the --enable-mysql-replication=y and 
           --enable-mysql-replication=n now work correctly. Any C 
           programmers might want to take a look at the vmysql.c
           file to see how #ifdef MYSQL_REPLICATION and the use
           of redefining symbol names for variables and functions
           work to simplify the code.

4.10.11
06/03/01 - update vldap.c to not look at ld_errno field and instead use
           the ldap_add_s return code. 

         - update configure.in for --enable-ldap=y to add -lresolv to
           the link libraries.

06/01/01 - finish voracle.pc port
         - fix the location of id for solaris machines

4.10.10
05/29/01 - vchkpw printf format error for uid/gid
         - configure wasn't printing out the correct auth_libs line
         - Sean Truman
           vmysql module modified to have a read and update connection.
           This can be used in mysql replicated systems.

4.10.9
05/25/01 - update configure script to accept --enable-sqlincdir=
           and --enable-sqllibdir= for the oracle module. 

         - vsetuserquota now forces "noquota" to be in upper case.
           vsetuserquota user@domain noquota becomes
           vsetuserquota user@domain NOQUOTA

         - vpopmail.c clean up for solaris, pid_t and islower int types

         - oracle version working.

4.10.8
05/24/01  "Sean C Truman" <sean.truman@prodigysolutions.com> 
         - vchkpw was exiting on successful authentication when 
           logging = 1 or 4.

         - update mysql module to use unsigned int instead of
           timestamp type. Then we store the unix system time.

         - a bunch of clean up of mysql authlog table stuff
           the time stamp in the authlog table is now a 
           time_t variable, or what ever is closest. In mysql
           it is a "bigint" type.

         - more POP_AUTH_OPEN_RELAY to remove the requirement
           for tcprules. If they don't want pop auth, they 
           are not required to have tcprules nor any of the
           vpopmail tcprule dependent code

         - fixed some return code stuff 
4.10.7
05/22/01 - "Sean C Truman" <sean.truman@prodigysolutions.com> 
           add bigdir features to vadddomain so domain directories
           can be hashed. Tested with cdb and mysql modules
         - master_domain dir control is updated on creation and
           deletion of domains.

         - change to configure script, if --enable-roaming-users=y
           is not selected, configure no longer checks if there
           is a valid tcprules program on the system, since it
           is not needed by vpopmail.

4.10.6
05/21/01 - Start updating voracle.pc to bring it current. Add in
           last auth, clear pass and valias features.

         - create vget_lastauth function in cdb module to return
           the last access time of the user. 

         - create vget_lastauth function in mysql module

         - change name of vlogauth() function to vset_lastauth();
           updated vmysql.c and vcdb.c to use new name

         - update vcdb vset_lastauth to put the remote IP into the
           lastauth file.
   
         - update vuserinfo to display last auth time if it is configured

         - update vchkpw.c to have ifdef for ENABLE_PASSWD

         - update configure script to report if system passwords are on/off

         - The valias_insert functions no longer check if user@domain is
           in vpopmail and replace with Maildir path 

         - removed the unneeded safestring.c files and functions
           instead use the standard string.h functions

         - complete re-write of vdelivermail.c 

4.10.5
05/20/01 - complete re-write of vchkpw.c removed need for vchkpw.h file 

         - vpopmail lowerit(char *string) now limits the string length
           as well as lowering it. Length is limited to 156

05/19/01   Chris <chris@hkseek.com> and Seo David <linuxqna@hotmail.com>
         - the following needs to be in the configure files
             *-*-solaris*)
            idcommand="/usr/xpgr4/bin/id -u"
           instead of /usr/xpgr4/id -u

           <new@hlmc.0451.net>
         - solaris reports problems with uid's and gid's declared
           as int's. They need to be declared as uid_t and gid_t

           Justin Heesemann <jh@ionium.org>
         - New code for cdb_to_sql function in vconvert. Very slick!

4.10.4
05/16/01
         - in vauth_setpw function for cdb, mysql and sybase, 
           change the check for VPOPMAILUID and root to check
           for uid = the uid in users/assign file for the domain
           and root. This will allow users who have thier domain
           stored under thier uid to be able to modify thier
           own users. Matt Simerson discovered the problem.

         - added loop checking in vdelivermail

         - set the permissions correctly on the new mail files
           in vdelivermail.

4.10.3
05/16/01
         - remove the need for a temp file for alias delivery
         - vdelivermail no longer writes to the Maildir/tmp
           directory and rename it to Maildir/new. Instead it
           writes directly to Maildir/new. This saves a system
           call to rename the file.
         - vdelivermail no longer stats the "to be created"
           Maildir/new file. This saves a stat system call

         - added new vpalias.c module for the vpopmail library
           that has the .qmail file based valias api functions.
           it is conditionally compiled in if mysql and valias
           are not used

         - non api commands completed for processing of .qmail files.  

         - configure script only allows --enable-valias=y if you
           have --enable-mysql=y

4.10.2
05/16/01   gilh@mudbuginfo.com
         - xinetd style line for pop/vpopmail in INSTALL file

           kbo@inter7.com
         - remove unused --enable-admin-email configure option
         - updated vmysql.c create table routines to use separate
           sql command buffer so the calling function doesn't need
           to reformat it's sql 

         - update all of the alias commands in the mysql module

         - updated vdelivermail to use the alias commands and
           support &emailaddress, emailaddress and directory
           deliveries. Sending the email into a program isn't 
           completed yet.
           
4.10.1
05/14/01 - vmysql.c vauth_setquota didn't finish the mysql command
         - added second mysql connection for vauth_getall
         - vauth_getall now uses store result instead of use result
           so that updates to the table can continue while other
           sql programs are accessing the table. 
         - change all mysql use_result to mysql_store_result

05/10/01 - vdeldomain will now delete all entries in the lastauth table
           for that domain if auth logging is enabled.

         - the authlog table creation function had remoteip as a column
           name instead of remote_ip, fixed

         - vdeluser will now delete the users entry in the authlog
           table if it auth logging was enabled.

05/09/01 - vadduser with mysql option and auth-logging option will
           now add a entry to the authlog table when ever a user
           is added, with a remote IP set to 0.0.0.0.

         - new vdeloldusers program to clear out any users which
           have not authenticated in X amount of time.

05/02/01
         - added check for max size of username
         - vdelivermail scopy sizeof(prefix) instead of sizeof(bounce)
         - vdelivermail won't make directories for unknown users

         filippo@mobilia.it & kbo@inter7.com
         - added check if mysql is down, email is deferred instead of
           bounced or deleted.
         - found two consecutive returns in vpopmail.c - removed redundant one
         
         - updated vldap.c vwrite_dir_control to have uid_t and gid_t
         

05/01/01 - kbo@inter7.com
           new version number for struct vqpasswd to be compatible
           with qmailadmin-0.50
  
         - created convert directory with new vcalias program that
           loads a domains .qmail files into the valias mysql table

         - added --enable-valias option to configure
           added VALIAS define to config.h 
           added VALIAS #ifdef code to vauth.h
           added skeleton VALIAS #ifdef code to vcdb.c
           added working VALIAS #ifdef code to vmysql.c

4.9.11
05/01/01 - Greg Nelsen <excalibr@avalon.net>
           Discovered why vpasswd keeps getting corrupted on his machine.
           vadduser() in vpopmail.c was not checking the return error
           code on make_user_dir() function. Hence it would crash.

04/30/01 - kbo@inter7.com
           removed vauth_vpasswd api (deprecitated), replaced
           functionality of vpasswd call with vauth_setpw()

           added --enable-clear-pass=y option to configure

           added support for clear passwd's to mysql module

           added support for clear passwd's to vcdb module.

           modified vuserinfo to display clear passwords if selected.
                                     
           updated vmoduser to allow setting encrypted password or
           cleartext password -C "clear text"

04/25/01 - Nathan <nathan@0x00.org>
           fixed file descriptor leak in vget_assign()

         - kbo@Inter7.com
           change mysql "unique index" to "primary key"

         - added vqpasswd structure to replace "struct passwd"
           this is needed to support clear text passwords and
           is a good stepping stone to adding support for other
           needed fields in the future. 

4.9.10
04/03/01 - Upgrade development release to production release

4.9.9-3
Mar 22 - vmoduser now will display an entire domain with a new option
         -D domainname

Mar 19 - configure now reports default domain

Mar 16 - remove #ifdefs for HARD_QUOTA in vdelivermail so that quota
         support is controled by the pw_shell (quota) field.

       - cleaned up error printf's for vdeldomain, vadddomain and vadduser 

       Bill Shupp
       - added --enable-logging=v option

4.9.9
Mar 15 - found correct path to /usr/xpg4/bin/id for solaris, updated
         the configure script

       - add error print out to vipmap if ip-aliases were not configured

       - remove unused tmpstr variable from vchkpw.c

       - --enable-log-name was not being used in vchkpw.c - fixed

       - vchkpw was not opening syslog before the first two possible
         calls to log an error then exit. fixed

       - r_mkdir was not using the incoming uid/gid and instead setting
         it to the hard coded VPOPMAILUID/VPOPMAILGID - fixed

       - problem with new safe_rename function, had the #ifdef reversed

       - fixed problem with vpopmail.c vgetent() function. It was not
         removing the trailing "\n" from the pw_shell field. 

Mar 14 - support for solaris not having the gnu id program

       - configure.in script was creating tcp.smtp file with wrong syntax

Mar 13 - finally idea for putenv is to use global variables instead
         of calling malloc. Slightly less processing time needed.

       - add AUTOMAKE_OPTIONS = foreign no-dependencies to 
         Makefile.am to be more portable

Mar  9 - add new vcdir program in the contrib directory. It will
         convert old .dir_control files into the new mysql table
         dir_control

       - added new informational printouts to the configure script.
         this might help folks see what got configured. 

       - new --enable-coda option and new coda link/rename code
         Thanks to "Andrea Cerrito" <cerrito@centromultimediale.it>

       - added new options to vconvert
         -v to print out the vpopmail version
         -d to enable debug print outs
         -S to set sqwebmail passwords for old domains which don't have them

Mar  8 - remove un-needed fsync calls in vdelivermail 

       - add check in make_user_dir for if user doesn't exist yet.

       - replace the link() functions in vdelivermail with a safe_link
         This might make vpopmail work on CODA file systems. Thanks
         to Jan Harkes <jaharkes@cs.cmu.edu> of CODA for the code
         snippet.

       - cleaned up the configure.in script and it's use of vpopmail.dir,
         vpopmail.uid and vpopmail.gid files

       - configure automatically creates the ~vpopmail/etc directory if
         it doesn't exist

       - added checks for vpopmail user and vpopmail group, cleaned up
         check for vpopmail home directory

       - added information message to make install-strip to let folks
         know they don't have to wait around while the chown/chgrp 
         runs, they can stop it if they want. it's knot really needed.

       - fixed vchkpw() putenv values in vchkpw.c 
         Found by "Boian Bonev" <boian@bonev.com>

Mar  7 - make vauthlog a function for each module, only mysql module has code.
         This is so sqwebmail and courier-imap can have thier authentication
         logged.

       - cleaned up code in make_user_dir() in vpopmail.c
         also creates sqwebmail password file if enabled and updates the
         authentication information

       - updated vchkpw to use the new make_user_dir code

       - updated vdelivermail to use the new make_user_dir code

Mar  6 - vmoduser wasn't working for entire domains. Simple fix.

Mar  5 - add -u NO_DIALUP code to vmoduser
         "Abdul Rehman Gani" <abdulg@eastcoast.co.za>

       - updated all code to use uid_t and gid_t instead of int.

       - vset_default_domain was over writing things at the wrong time
         in the mysql module

Feb 28 - Added configure check to see if it's being run as root.
         It needs root access to write to the !vpopmail/etc directory.

       - fix compile time warning with ip-alias-domains=y

       - fix vipmap -p for cdb module. it wasn't printing anything.

Feb 24 - for mysql, allow ' character in gecos field

       - vconvert -c -s wasn't setting the uid field correctly

Feb 23 - Don't allow zero length or null user names in vdeluser. 
         This would cause an entire domain to be deleted

       - added logging of pop authentication with mysql module

           - vdeldomain now prints out correct error message when it can not
         to delete a domain.

       - fixed vadddomain -e user@domain option

4.9.8-1
Feb 19 - qmail-newmrh instead of qmail-newrh in execl call
                 "Oden Eriksson" <oden.eriksson@kvikkjokk.net>

Feb 16 - nice vacation, sqwebmail-pass fix

4.9.8
Jan 10 - audit vchkpw default domain, ip aliases and parsed domain code
         minor fix

Jan 9  - bug in the ldap module caused qmailadmin to not list all accounts

Jan 8  - add virtual IP and bigdir functions to ldap module

       - add -e "encrypted password" option to vmoduser

Jan 4  - move IP aliase code to vpopmail library

       - make vset_default_domain read VPOPMAIL_DOMAIN environment varilable
             redo the logic

Jan 3  - upgrade to next version number

       - remove .qmail forwarding loop in users Maildir .qmail file

           - remove string length check for mysql ip alias mapping

           - add VPOPMAIL_DOMAIN environment variable check in vset_default_domain
             this is handy for <VirtualHost > SetVar

4.9.7    "The quest for distributed data synchronization via 
          transaction oriented data storage, e.i: RDBMS"
                  or
          "No more vpopmail vpasswd, .dir-control file locking"

Jan  3 - removed unneeded alarm call in vdelivermail

Dec 22 - option setting in vpasswd for apop was reversed.
         Oliver Chiu <oliver@conexys.com>

Dec 18 - added vdirrestore shell script to contrib directory.
         "Sailin Nelson" <scn@homernet.net>

Dec 14 - add quota flag to vmoduser for setting the quota

       - patch files for cistron 1.6.4 radius server added to contrib
         directory. enables cistron radius to use vpopmail api for
         authentication transactions (Nice work)
         "Abdul Rehman Gani" <abdulg@eastcoast.co.za>

       - changed the order the cdb files update vpasswd so as to use
         the rename(2) function "it will be atomically replaced"

       - remove the need to have file locking on the .dir-control file
         with cdb module.

       - modified the update_file utility function to use the automic
         rename(2) unix function.

       - modify the open_smtp relay file i/o to use the automic rename(2)
         for updating the file

       - update the configure script to automatically search for the
         mysql library and include directory in the two standard locations.
         also check if it's not been found and force the user to set them
         as configuration line options

       - configure script now creates an ~vpopmail/etc/inc_deps and
         ~vpopmail/etc/lib_deps files that contain the needed -I
         and -L -l options for other programs that use the vpopmail code

       - null terminator addition code fix for parse email.
         "Abdul Rehman Gani" <abdulg@eastcoast.co.za>

       - modify the mysql create table syntax for the relay table to use
         unique index instead of primary key. Since the update sql requires
         updates against a unique key

       - create mysql functions for dir control i/o using replace sql
         for synchronizing access to the dir control state information
         per domain.

       - add -lz to default mysql libraries needed

       - fix default domain and ip alias domains working with each other

NOTE: qmailadmin-0.40 configure/makefile scripts were updated to use the
      inc_deps and lib_deps files to automatically figure out which include
          directories, lib directories and libraries for vpopmail's setup

Dec 13 - added new vipmap command line program to add, delete and print
         out the list of IP's and their associated domain name mappings

       - removed DNS/tcpserver code for ip alias domains and instead use
         new vpopmail api functions: vget_ip_map, vadd_ip_map, 
         vshow_ip_map and vdel_ip_map 

       - added new ip map code to vcdb.c module

       - added new ip map code to vmysql.c module

       - added ifdef's inside each include file to exclude multiple inclusions
         (The above line is my nomination for the trippiest ChangeLog wording) 
           
       - added contrib directory to the distribution. First entry is, vpassgen 
         a script that will rebuild a vpasswd file from the directory
         structure of an existing domain ;] Then all you have to do is
         deal with customers calling and complaining about passwords.
         "Sailin Nelson" <scn@homernet.net>

       - modularized the big_dir i/o api functions.

       - moved file based big_dir i/o functions to the cdb module.

       - added mysql big_dir i/o functions.

Dec 12 - cdb module now allows the uid/gid owner of a domain to set a
         password or update the password structure.
         Brian Kolaci wrote the code. Thanks to Matt Simmerson for 
         sending it in and using it on his boxen.

       - update how vchkpw calls vclose to cleanly close mysql connections
         on pop authentication. This removes those horrible "aborted
         connection" messages in the mysql error log.

Dec 11 - log user, host, ip and password for users who are denied pop 
         access yet attempt to connect via pop. 
         "Chris Bunnell" <macgyver@sonicisp.net>

Dec 10 - update the vmoduser usage comments to include the V_USER0 through
         V_USER3 flags. Update the GidFlag bit flag setting in the option
         processing to correctly set the flags.
         "Abdul Rehman Gani" <abdulg@eastcoast.co.za>

Dec  9 - vmysql module didn't unmangle ip address from courier-imap users

Dec  6 - added -d option to vadddomain for setting the directory on
         the command line.

Dec  5   fixed apop usage in vmysql.c 

Nov 30 - free memory in vcdb.c under error condition
         "James" <daemus@oregonfast.net>

Nov 27 - vsqwebmail_pass was writing over TmpBuf1 in vadduser so
         that the chdir back to the callers directory was not working.
                 Martin Köster <mk@ezl-data.dk>

Nov 20 - add a res1=NULL in vmysql.c vauth_getall to make it more
         robust.  Garrett Marone <garrettm@web2010.com>

Nov 15 - vchkpw forces all pop names to lower case

4.9.6
Nov 13 - upgrade version to 4.9.6

4.9.5
Nov  1 - udated vmysql.c voracle(pc/c) vsybase.c and vldap.c to 
         correctly set the sqwebmail password

Oct 31 - logic error in vget_assign with memory freeing

       - Happy Holloween!

       - commenting code in vpopmail.c, removing static strings for
         calloc'd memory.

       - --enable-logging=y and password would fail, then no
             string was formatted so blank entry to syslog, fixed.

Oct 30 - moved the SQWEBMAIL_PASS define into configure program.

       - found error in vcdb.c module. it was not setting the
         sqwebmail password when called by vauth_setpw api

       - memory and FILE * leak in vchkpw.c fixed
         Brian Kolaci <bk@Kola.com>

       - NoMakeIndex and ClearFlags option command line flags were
         set to the opposite of what thier defaults should be
                 Daniel Augusto Fernandes <daftm@gcsnet.com.br>

Oct 25 - added error checking to vauth_getall in all auth modules 

       - moved the open_smtp_relay code into the vpopmail library
         so courier-imap can do roaming users. removed the opensmtp files

Oct 24 - vget_assign had a strncmp != 0 and should have been == 0 

Oct 23 - lower the case in vdelivermail for user and domain after
         the values are filled in from the environment variables.
         submitted by RP <rp@nrp.de>

Oct 19 - vcdb.c - set fsv NULL when vauth_getall has no more users

       - vaddaliasdomains was not setting the path to the domain
         correctly, due to the switch to multi uid/gid, fixed.

Oct 17 - update configure.in to use ps -aux instead of ps -ef for
         openbsd platforms

       - add vcloses to all programs. This should remove mysql 
         warning messages about aborted connections if mysql is
         setup to report aborted connections.

       - add -i uid -g gid to vadddomain

       - update confingure.in to set USE_SQL for oracle and sybase.

       - update usage printouts in vadddomain, vadduser, vdeluser, 
         vdeldomain, vuserinfo, vsetuserquota, vaddaliasdomain,
         vpasswd, vaddaliasdomain

       - updated vuserinfo to print out gid flag values and what they mean

       - update vuserinfo to print out default domain name when no user
         is found and you are searching the default domain, 
         for example: ./vuserinfo user

Oct 16 - remove check for .overquota-msg in users dir, only use domain
         based .overquota-msg files

       - new quota checking code. checks all emails in all directories
         under a users directory. uses a status file to minimize disk i/o

Oct 12 - make the uid APOP field be a bit flag

       - update mysql, sybase, oracle and ldap modules to support
         non vpopmail uid/gid domains.

       - vclose in voracle.c was declared int vclose() should have been
         declared void vclose(), fixed

Oct 7  - add new USE_CDB define to configure scripts

       - update vmkpasswd.c to use the USE_CDB define, so non cdb 
         authentication modules don't complain during make.

       - have tcprules build the temp file in the tcp.smtp directory

       - have mysql module return error on no connection 

       - Update INSTALL to note that a home directory is 
         required for installation

       - slen return 0 if passed NULL parameter

       - if default domain is configured, not all /etc/passwd accounts 
         work, fixed

       - update vmoduser to use getopt add -n option to not re-build 
         vpasswd.cdb file

Oct 6  - vadduser: fix command line parsing, fix core dumps on incomplete
         command line options, add check for ctrl-D break out of 
         vgetpassword function. 

       - updated vauth_getpw in cdb module to return error if program
         does not have permission to get a write lock

       - updated vuserinfo to have new output syntax, plus will output
         all fields for a user if no options except email address is given.

       - removed redundant chdir() in vadduser in vpopmail.c

       - integrated Krzysztof Dabrowski changes to the source code for 
         setting up domains under /etc/passwd users other than vpopmail.

       - New check in vadduser function in vpopmail library to not
         allow email addresses with one letter in the user name. 
         For example, a user named 0 will conflict with the bigdir
         algorythm that creates a directory named 0 to store the
         100-199 users. 

4.9.4
Sep 22 - modify safestring.c sstrncmp to return correct value if
         comparing a subset of two longer strings
        
       - vchkpw will autocreate a user directory if thier path value
         in the authentication structure is empty.

Sep 21 - autocreation of directories would cause vdelivermail to core 
         dump if pop account does not exist

Sep 20 - updates to FAQ file

4.9.3

Sep 18 - fix up vclose is_open login in vmysql.c vsybase.c voracle.c

       - vdelivermail will auto create a users directory if thier
         directory value in thier authentication structure is blank.
         This can be used by sql based systems, or ldap systems.
         Users can be created and inserted into the database, and
         if their path value is left blank, vpopmail will use the
         bigdir directory layout algorythm to create a directory
         and update the authentication database. So, users can be
         created by just adding them to the database and leaving
         thier directory path blank.
         
Sep 16 - remove perror print outs from file_lock.c

       - add -p file option to vconvert to convert a file of
         user<token>crypted_password entries into a domain.

Sep 14 - vmoduser now lets a whole domain be set

Sep 12 - update the ldap code to support setting/getting the uid, gid
         gecos and shell (mail quota) fields.

Sep 11 - replace locking code in vpopmail.c and vcdb.c with new file 
         locking code from Eric Peters

4.9.2
Sep  6 - add version switch to all v* programs, either with -v option
         or in the default usage statement

       - vadddomain prints out usage statement if no domain is specified

Sep  5 - set tcp.smtp.tmp file in the dir with open-smtp. fixes some
         "ack child crashed" messages

Aug 25 - set global close flag for mysql module fixes sqwebmail/mysql bug

4.9.1  
Aug 24 - add --enable-logging=p to log failed passwords. New
         default does not log the password.

       - Add new locking code patch from Eric Peters

Aug 21 - add sstrcmp and sstrncmp functions to safestring.c

       - replace all strlen, strcpy, strcmp and strncmp with
         functions in safestring.c

4.9
Aug 14 - lots of new ldap code

4.8.9
Aug 9  - changed getuid to geteuid so setuid programs work.

4.8.8
Jul 27 - added vuserinfo program to display fields from the password
         information.  

Aug 2  - input checking bug in safestring.c scopy fixed

Aug 4  - memory allocation error in vchkpw log_pass_fail routine
         would cause an -ERR aack, child crashed if the password
         was too long. fixed.
        
Aug 7  - add vmkpasswd program to the Makefile

Aug 8  - In the vadddomain program, check the status code of the
         vauth_getpw call before calling vsqwebmail_pass

4.8.7
Jul 27 - Update the auth modules to do a getuid to check if the
         uid = vpopmail or root, for changing the passwd files
         in any way, vpasswd or vmoduser.

       - changed vmoduser and vpasswd programs to print error return

       - fix case sensitivity in aliased domains

4.8.6  - have the configure script look for /usr/bin/tcprules as
Jul 07   well as looking for it in /usr/local/bin/tcprules

Jul 24 - removed unneeded fsync call in vdelivermail
       - removed unneeded alarm and sig alarm handler in vdelivermail
       - added vdelivermail filter code from Matthias Henze as
         a new configure --enable-deliver-filter option
    
4.8.5
Jul 07
       - some code and configure clean up

       - added vclose call to ldap module

4.8.4
Jul 03 - force lower case incoming user@domain in vdelivermail.c

       - add vclose function call to close the connection to the database.
         This is needed in courier-imap so the database connection isn't
         kept open.

       - added sybase module

       - Set vpopmail uid/gid for tcp.smtp.cdb and open-smtp files
         when called by clearopensmtp program.
     
Jun 30 - removed drop index call in mysql, oracle. they are no longer needed.

4.8.3
Jun 29 - oracle module added

       - memory leak in vauth_getpw in mysql module fixed

       - added primary keys to the vpopmail tables for both
         large and small site layouts. Also restrict domain
         size to varchar 223

       - changed the default to turn off HARDQUOTA

4.8.2
Jun 28 - rewrote the configure.in and Makefile.am for new 
         method of handling authentication module source
         code and libraries. mysqlclient objects are no
         longer archived into the vpopmail library.

       - added beinging of an ldap module. If currently only
         supports the vauth_getpw call. Which is enough for
         vchkpw and vdelivermail to work, as well as sqwebmail
         and courier-imap.

4.8.1
Jun 28 - added primary key to mysql relay table to make mysql
         replace work. No more duplicate IP's

       - allow usernames with trailing "-", ie: joe-@test.com

       - reviewed and changed all the permission setting code.
         removed some unused calls. Moved all the definitions
         for permissions to the vpopmail.h file.

4.8
Jun 27 - use getpid() to create a unique file name for tcprules
         in opensmtp.c roaming users option.

       - vchkpw syslog entry changes. No more var args, now more
         static buffer size, checking of all syslog message text
         for '%' character

Jun 22 - Added authlib directory to the subdirs in Makefile.am so
         that make distclean will clean out the .o's in that dir.

4.7
Jun 22 - remove the automatic creation of vpasswd.cdb files to
         remove two "stat" function calls for email email and
         pop access. The vpasswd.cdb file is still (re)created
         when any function modifies the vpasswd file.

         Note: If you edit the vpasswd file by hand, you will
         need to run the vmkpasswd program

       - added a vmkpasswd program to create a vpasswd.cdb file
         from a vpasswd file for a domain.

Jun 13 - added debug and backdoor ifdefs to vchkpw.c

Jun 12 - fixed (hopefully for all time) the dir to users Maildir for
         cdb and mysql. 

       - fixed the vconvert from cdb to mysql for user directories

Jun 10 - Check for : character in gecos field and return error if found.
         vpasswd files are parsed using the : character. If spurious
         : characters are in any of the fields, we have a problem
         parsing the lines.

Jun 07 - Ondøej Surý - fixed possible memory problem with handling
         the HOST environment variable in vdelivermail.c 

4.6
Jun 07 - set RBLSMTPD environment variable for roaming users

Jun 05 - automatically create user directories if they are in the
         password database under two cases. 1) when mail is delivered
         by vdelivermail and 2) when the user pop authenticates

Jun 02 - Correctly names email files with Maildir++ names. Speficically
         it includes the size of the file in the name ...,S=nnnn where
         nnnn is the file size

       - Uses Maildir++ file names to calculate the size of the email
         file instead of stat'ing each file.

Jun 01 - added "delete" as an option to vdelivermail to erase
         incoming emails for non matching accounts.

4.5
may 31 - fixed default domain code in vpopmail.c and vchkpw.c

       - stray mkstemp/mktemp files were being left behind, fixed

       - fixed extra directory formatting in vauth_adduser_size

4.4
may 26 - fixed use of the ATCHARS "@%/" for parsing user@domain

may 25 - fixed configure to get the correct ps arguments for BSDI

may 24 - opt fixed some things in the configure.in and Makefile.in
         so that mysql configures nicer

4.3
May 23 - extend the gid bit flags to include 4 user defined flags

       - updated vmoduser to set/reset new flags
4.2

May 22 - fix the command line processing in vaddaliasdomain

       - fix configure to always compile in the cdb library even
         for mysql. new vpopmail api call uses cdb functions

       - optimize rebuilding of tcp.smtp.cdb for --enable-roaming-users=y
         checks to see if the IP is already in the file.

       - aliasing of one domain to another with vaddalias domain works
         for both cdb and mysql and delivery and pop auth. everything.

4.1

May 21 - have vchkpw wait for tcprules to complete if using roaming-users=y
         so we don't get zomebie processes.

       - fixed vsetuserquota to support an entire domain 
         ./vsetuserquota test.com 5 would set the entire domain
         quota to 5 bytes
     ./vsetuserquota test.com NOQUOTA would set the entire domain
         to not have a quota

       - cleaned up the buffer reading code from file descriptor 3

       - documented some more code in vchkpw.c
 
May 19 - memory leak in vcdb.c vauth_getpw fixed

       - memory allocation bug in vcdb.c vauth_getpw fixed for
         default domain stuff

3.4.11-2

Apr 04 - create ~vpopmail/etc dir on make install

       - move assumed tcp.smtp file to ~vpopmail/etc

       - move open-smtp relay file (for cdb auth) to ~vpopmail/etc dir
         This along with the tcp.smtp file move allows tcpserver to
         run the pop deamon as vpopmail/vchkpw instead of root 

       - .qmail-default files are now created with "bounce-no-mailbox" 
         as the default setup. I think this is safer than letting unsuspecting
         domains fill up thier postmaster mailbox 

       - removed support for "defaultdomain" file ni ~vpopmail/domains
         Now it is only supported by --enable-default-domain

       - added vadddotqmail function for setting up single or multi line
         .qmail-<user> files

Mar 30 - fix the Delivered line to not have the virt domain before the user

Mar 29 - use the replace function of mysql in vmysql.c vopen_smtp_relay
         function for storing the relay IP's

       - vpopmail's config.h is also copied to 
            ~vpopmail/include/vpopmail_config.h

       - removed all error printf's from vpopmail libary and replaced them
         with VA_error codes
       
       - Updated FAQ with how to get vpopmail working with IMP and
         courier imap (thanks)

       - all functions that change dir return to the orignal directory
         before returning.

Mar 28 - add new error return codes and char *verror(int) function

       - vadduser API now correctly returns to the cwd

Mar 16 - change getpasswd to vgetpasswd HPUX compatiblity 

3.4.11-1
Mar 14 - fix file permissions on .vpasswd.lock and .dir-control

Jan 24 - change to INSTALL file for running pop3d server as vpopmail/vchkpw
   
       - added additional bounce checking

Jan 20 - Bounds checking for buffer overflow

Jan 19 - Fixed --enable-default-domain error in vpopmail.c

Jan 15 - modified error logging of bad passwords to print out clear
         text password. This could be a risky thing. but based on
         system administrators real life experience, it helps them
         do thier job if they can see what the user is typing.
         Hence we show this information. 

Jan 14 - in vchkpw, made user and host global variables for logging. 
         example: vchkpw: No user found [jojo@bab] from 127.0.0.1

       - Found some code logic flow errors and fixed.

       - standardized error and login log output messages in vchkpw.

       - vauth_getpw no longer modifies the incoming host parameter value.
         instead it mallocs a local variable.

Jan 13 - changed mysql query to use_result instead of store_result
         which was causing a buffer overflow in the temp IP for relay

       - added IP to No user found line

       - started work on mallocing buffers instead of declaring them
         big enough to not be over run

Jan 3  - tcprules was being called with "tcprules file.cdb file.cdb" 
         when it should be called with "tcprules file.cdb file.tmp"
         So it is now modified to call it with "tcprules file.cdb file.XXXXXX"
         where the 6 X's are replaced by mktemp(3)

Jan 3  - updated the mysql modules to store the temporary IP relay file
         in the database instead of in /etc/open-smtp. No more file
         locking needed this way.

dec 31 - set default gecos field to user name in vadduser program

dec 30 - put error check on lock function, exit with errors

dec 28 - added -s flag to vadduser command to speed up indexing. with -s
         the vpasswd.cdb is not updated, and will update on next mail
         delivery or pop3 access.

dec 27 - added cdb subdirectory and removed the need for ucspi-tcp package

dec 20 - modified bigdir.c and bigdir.h to make the max depth and
         max users per level to be #defines

dec 18 - found typo in large table sql definition for mysql.
         was using char and not varchar

dec 17 - added .no-user.msg for setting bounce message for no user

dec 14 - missing closedir() in vconvert

dec 13 - added directory walking code to vpopbull. the list of domains does
  not need to be specified. If not specified then all domains will
  receive the email.

dec 13 - optimized initial mysql connection to use mysql_real_connect.

dec 10 - added run time support for setting default domain. Create a 
  file in ~vpopmail/defaultdomain holding the default domain name.
  This is over ridden by the compile time DEFAULT_DOMAIN option.

- Added new parameter to vadddomain api call to make a domain the
  default. Pass 1 if you want it to be default, pass 0 if no.

- Added new -d flag to vadddomain command line program to set
  a domain to be the default. 

- updated error logging in vchkpw to say vchkpw instead of main. Also
  added user name to error log if not found. 

- fixed a few bugs that caused core dumping if the pw_data struct was NULL

- fixed a bug in local user lookups under freebsd 3.3.

- added "no dialup" flag to vmoduser

- added support for setting gecos field in all functions.

- vmoduser added -c "comment" field, clear flags is now -x

- vmysql.c module did not set the default quota on new user creation. fixed

- added vconvert from mysql to vpasswd.cdb files. needs to be compiled
  with --enable-mysql=y to work.

- added vmoduser program to restrict access to different email features
  no webmail, no pop, no imap, no password change, bounce email

- fixed bug in mysql module for vauth_setpw only effects in vconvert program

3.4.10

- added --enable-default-domain in configure script to allow setting the
  default domain name. users from the default domain don't need to
  specify thier domain name in pop (or in any other app that uses vpopmail
  libraries, like the upcoming releases of qmailadmin,sqwebmail,courier-imap)

- modified and tested the code to support default domain.

- added sortit parameter to vauth_getall. No effect for vpasswd/cdb since
  users are already sorted alphabetically. With mysql causes an order by
  pw_user to sort the results alphabetically by pw_name 

- renamed delfiles to vdelfiles for other apps that might use this function

- created libvpopmail.a file for other applications which need vpopmail 
  functions

- included support for including libmysqlclient.a files in libvpopmail

- included support for including cdb object files in libvpopmail

- included ucspi package in distribution. removed --enable-ucspi-dir

- vadduser checks for valid username characters and format.
  If invalid it returns -2 and prints a message.

- vadddomain checks for valid domain name characters and format.
  If invalid it returns -2 and prints a message.

- vadduser now adds users alphabetically in vcdb module

- cleaned up file permissions inside util.c

- user over quota now bounces email back to sender with new subject line
  and from postmaster@<virtualdomain>

- vconvert program allows conversion between default sql, cdb, and large sql

- message to qmail log removed unused blah:blah:blah stuff

- bounce message changed to look more like qmail

- if a user is over quota, messages of 1K or less are still delivered.
  This allows system admin programs to send an over quota message to a user.

- added default support for small user/lots of domains. New configure
  option --enable-large-site=y optimizes mysql for small number of
  domains with large number of users per domain

- updated API and command line programs to use utility functions:
    vadddomain, vdeldomain, vadduser, vdeluser, vpasswd, vsetuserquota 

- <virtualdomain>/<user>/.qmail file can have multiple email addresses 
   to forward to.

- added support for mysql. See README.mysql

- adduser function checks if the user exists first 

- updated INSTALL and FAQ files

- vadddomain, vdeldomain, vadduser, vdeluser, vpasswd, vmkcdb now display
  correct usage printout when given -h option. 

- vaddomain removes duplicate entries in /var/qmail/users/assign file

- fixed hupping qmail-send for some solaris platforms due to 
  "broken pipe" error. 

- Support for user-subname. For example: mail to user-subname is
  delivered to user. Before this user-subname was considered to
  be a full email name and would be bounced.

- switched all strcpy, strcat, strncpy and strncat functions to
  safe versions of scopy and scat, see safestring.c for details

- removed use of pophome variables in vdelivermail.c and vchkpw.c
  since it is a #define generated during configure

- made all vpasswd file names and cdb names #defined in util.h
  Makes it easier if you need to move the files to.. say.. err.
  perhaps..  an NFS mounted subdirectory. *cough*

- efficency change. switched to using the TCPLOCALHOST environment 
  varible for IP_ALIAS setting. --enable-ip-alias-domains=y. It removes 
  a dns reverse lookup by getting the value of the environment variable 
  set by tcpserver.

- If a hard quota is defined (default) then vpasswd file contains the
  actual hard quota instead of the words "NOQUOTA" when a user is added.

- modified vsetuserquota to set the quota for all users in a domain.
  vsetuserquota domain quota-in-bytes or
  vsetuserquota user@domain quota-in-bytes. Also excepts K and M
  for kilo and mega bytes. ie. vsetuserquota domain 1M

- added .qmail support within a users dir at the same level as
  the Maildir. The reason is to be able to turn on and off email
  forwarding for a pop user. And to place the .qmail file inside
  the users directory instead of at the base directory for the
  domain with a .qmail-user file. Sqwebmail will be modified to
  add a "turn on forwarding to this address" button in the options
  page.


- added vpopbull program to distribute an email to all users in
  a virtual domain. it can deliver to all domains or a single domain.

- removed fgetpwent requirements

- uses morercpthosts for sites with over 50 virtual domains
  full admin features, creates/deletes morercpthosts and morercpthosts.cdb
  during addition and deletion of virtualdomains.

- automated support for cdb versions of vpasswd user files

- updated error log report to include domain name when user not found
  during pop authentication.

- if ip_alias_domains is enabled, then check the virtual users first, 
  otherwise check /etc/passwd users first

- changed popen call to fork/execl in vchkpw for running qmail-newu. 
  popen isn't good, since it's dependent on the default shell, and
  not all versions of shells support popen in the same way.

- changed code in opensmtp.c program when it envokes tcprules. It returns
  an error instead of exiting with an error. Caused "Child Crashed".

- make install or make install-strip sets the user and group
  permisions on all the installed directories.

- SHELL=NOLOGIN is passed in vchkpw environemnt to qmail-pop3d.

- vadddomain now checks qmail/locals file and removes the domain name
  if it is there. Sanity check.

- Added "/" character to the "@" and "%" characters to use in
  pop names. Perhaps this could also be used in vsqwebmail.
  

3.4.9

- switched from using vsyslog to vsprintf and syslog. Digital Unix
  doesn't have vsyslog.

- added UID/GID vpopmail user home dir defines in config.h

- updated all code to not call getpwname for the vpopmail user.
  All references to homedir, uid, gid changed to use config.h values
  This should increase performance, especially on systems with large
  /etc/passwd files.

- fixed bug in setting --enable-vpopgroup

- new code for user directory splits for larger sites

- removed {} brackets around configure options for configure --help

- added -q quota_in_bytes option to vadddomain to set the postmaster quota

- added -q quota_in_bytes option to vadduser program to set the quota

- files gets locked by library routine when any modifications
    are being done. Prevents multiple programs from stepping on each other.

- new program, vsetuserquota, to set an individual users email quota
    in a virtual domain.

- Changed NOLOGIN string in vpasswd file to NOQUOTA. Will retain backward
    compatiblity with NOLOGIN. Updated vpasswd.c to support this change.

- #ifdef FGETPWENT changed to #ifndef FGETPWENT in vchkpw.c and vdelivermail.c

- vadduser checks if a user is in /etc/passwd before adding to ~vpopmail/users

- syntax error on buffer declaration when --enable-apop=n fixed

3.4.8

- per user quota's
    currently have to edit vpasswd file by hand. Change the last field
    in the vpasswd file from the default of  "NOLOGIN" to the number
    of bytes of the quota. If it is set to NOLOGIN it will have the
    quota set in configure

- disable hard quota code
    --enable-hard-quota=0 or --enable-hard-quota=n will turn off
   quota checking code.

- better logging with three --enable-logging options
    --enable-logging=y means log success and failure auth and fatal errors
    --enable-logging=n means log nothing 

    and the default is:
    --enable-logging=e means only failure auth and fatal errors 

- vpasswd reports error if trying to change password for non existant user.

- new program "vaddaliasdomain" to alias a new domain to a current domain.

3.4.7

- changed package name to vpopmail

- fixed configure error on solaris for -lnsl and -lsocket libraries

- fixed --enable-passwd=n option syntax errors

- removed no-user-check configure option

- tweaked chown chgrp install

- tweaked --enable-passwd=n code

3.4.6

- for sites that use ip's per virtual domain. vchkpw doesn't require
  the user to pop in with user%virtualdomain. it performs an IP reverse 
  lookup and uses the returned hostname as the virtualdomain. This
  hostname must match the virtualdomain name created with vadddomain.
  New enable option --enable-ip-alias-domains

- code cleanup

- opensmtp now uses the value of --enable-tcp-server-file to envoke
  tcprules with the correct file if it has been changed during configure 

- added --enable-tcprules-prog in the configure script to allow placing
  the tcprules program in a location other than /usr/local/bin/tcprules

- added --enable-relay-clear-minutes to over ride the default (60) number
  of minutes before a roaming users IP will be cleared from the relay files.

- changed vadddomain to update rcpthosts and virtualdomains instead of
  just adding the new domain to the end of the file. Duplicates are 
  removed and only one entry with the domain will end up in the file.

- changed vadduser to use the same update code as vadddomain

- the open-smtp files are now placed in the same directory as the 
  tcp.smtp file. If the tcp.smtp file location is set with the
  --enable-tcpserver-file configure argument, the open-smtp files
  are put there too. The default is in /etc

- sets the files in ~vpopmail/bin to have correct uid and gid

- added --enable-admin-email to override the default admin email address.
  The default is set to postmaster@hostname, what ever hostname returns.

- added --enable-no-user-check to not check for the vpopmail and vchkpw
  user and group. This was needed to run the rpm that is being developed.

3.4.5

- force usernames and domains to be lower case in vadddomain and vadduser

- replaced md5 code with GPL'd source instead of the RSA code

- fixed inclusion of fgetpwent module in binaries on systems that 
  already have fgetpwent in the system libraries. 

- removed "_" character from list of allowable "@" replacements.
  Now only "@" and "%" are allowed for delimiting user and domain
  This allows email addresses to have "_" in the user name, like:
  joe_blow@one.com

- added check for null user, host or prefix to vdelivermail to exit
  with error instead of core dumping. 

3.4.4

- fixed bsd need for fgetpwent in Makefile and source

- Added FAQ file

- if qmail-send is not running, vadduser and vadddomain will not attempt
  to sig hup qmail-send 

- if control/virtualdomains or control/rcpthosts files don't exist
  vadddomain would set the permissions wrong. They are now set correctly
  to be read/write user, read group, read other.

- added the ability to bounce mail if a pop user or .qmail file
  doesn't exist.

- fixed redhat 5.2 /etc/passwd authentication with no shadow. 
  It was a configure defines setup

- fixed Makefile problems for solaris platform (might fix BSD too)

- fixed file permissions on the distribution files.

- added default mode on users/assign file to read/write owner, read group
  read other.

- added -a switch for vpasswd to set APOP for that user.

- added file locking with fcntl for the open relay after pop authentication.
  heavily popped sites were getting errors when two pop authenications
  tried to rebuild the /etc/tcp.smtp.cdb file at the same time.

- added a configuration option --enable-tcpserver-file to set the
  default /etc/tcp.smtp file to something different.

- added -a switch to command line argument for vadddomain to use APOP
  for the postmaster account for that domain.

- added -a switch to on the command line for vadduser to use APOP for 
  that user.
 
3.4.3

- added vpasswd command to change the password for any user or user@domain.

- moved users vpasswd file into ~vpopmail/users instead of in ~vpopmail.

- configure support.

- auto detects shadow password.

- installs into ~vpopmail/bin ~vpopmail/users ~vpopmail/domains.

- C version of vaddomain, vdeldomain, vadduser, vdeluser.

- vaddomain renamed to vadddomain.

- hard quota default set to 50meg per user.

3.4.2:
- By default any mail that doesn't match a pop account gets delivered to
  postmaster. In this new version the default account can be at a remote
  location. The change is in the .qmail-default file. 

- User quota hard limit (set to 10 meg). When hard limit is reached, all
  email is bounced back to sender. 

- Force 0644 file permisions on /etc/tcp.smtp.cdb 
  Opens smtp relay for 1 hour after pop authentication. This works in
  conjunction with the tcpserver -x /etc/tcp.smtp.cdb feature. 

- User mail quota hard limit. 

3.4.1

- Fixed case insensitivity problem

