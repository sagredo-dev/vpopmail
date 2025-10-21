`vrcptcheck` is a recipient check for `s/qmail`

Just call this program within */var/qmail/control/recipients* as follows:

```
echo "*|~vpopmail/bin/vrcptcheck" > /var/qmail/control/recipients
```
