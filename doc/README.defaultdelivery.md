# README.defaultdelivery

by Roberto Puzzanghera  
More info [here](https://www.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html)

==============================================================================================================

When `vpopmail` is installed with `--enable-defaultdelivery` then `vdelivermail` is installed by default in
_.qmail-default_ of newly created domains with option 'delete'.  
If no user's valiases and no _.qmail_ are found, then the message is sent to the _control/defaultdelivery_ file,
so that `dovecot-lda` (or whatelse) can store the mail into inbox and execute the sieve rules.  
If vdelivermail is found in _control/defaultdelivery,_ then it is ignored to avoid loops. The delivery remains
in charge to _.qmail-default,_  i.e. `vdelivermail`.

## Settings

Configure as follows:

```
./configure --enable-defaultdelivery (default OFF)
```
