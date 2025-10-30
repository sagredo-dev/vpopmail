`vrcptcheck` is a recipient check for `s/qmail`

Just call this program within */var/qmail/control/recipients* as follows:

```
echo "*|~vpopmail/bin/vrcptcheck" > /var/qmail/control/recipients
```

You have to run `qmail-smtpd` as the `vpopmail` user in order to
run the `vpopmail` functions.
