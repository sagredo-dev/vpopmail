`vrcptcheck` is a recipient check for `s/qmail`

Just call this program within */var/qmail/control/recipients* as follows:

```
cat /home/vpopmail/bin/vrcptcheck > /var/qmail/control/recipients
```
You have to provide an `autoreconf -f -i` before configuring, as the original Makefile.am has been modified.
