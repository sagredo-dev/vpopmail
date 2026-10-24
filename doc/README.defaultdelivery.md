# README.defaultdelivery

`vdelivermail` is installed by default in _.qmail-default_ of newly created domains with option 'delete'.  

If no user's `valiases` and no _.qmail_ files are found, then the message is sent to the 
_~vpopmail/etc/vdefaultdelivery_ file, so that `dovecot-lda` (or whatelse) can store the mail into inbox
and execute the sieve rules.  

I the recipient user has a `valias` this is executed first. If a `valias` is like `:default`', then the
content of _~vpopmail/etc/vdefaultdelivery_ is executed.  
This allows the user to use forwards and then send a copy of the message to the Maildir.

NB: `vpopmail` versions before 6.7.x used to save `vdelivermail` in _QMAILDIR/control/defaultdelivery_ instead of
_~vpopmail/etc/vdefaultdelivery_.  
_QMAILDIR/control/defaultdelivery_ is not executed anymore by `vdelivermail`.
