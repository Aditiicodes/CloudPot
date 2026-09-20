# honeyfs overlay

Cowrie's emulated filesystem has two layers.

`share/cowrie/fs.pickle` supplies the **shape** of the tree - which paths
exist, their sizes, owners and timestamps. It ships with Cowrie and is not
modified here.

This directory supplies the **contents** of the handful of files an attacker
actually reads. When a session runs `cat /etc/os-release`, Cowrie serves the
file from here rather than inventing one.

The files are chosen for one reason: internal consistency. The SSH banner
claims `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`, `uname -a` in `cowrie.cfg` claims
`5.15.0-91-generic`, and `/etc/os-release` here claims Ubuntu 22.04.3. A bot
that cross-checks any two of those against each other finds them consistent.
Contradiction between banner and filesystem is the cheapest honeypot
fingerprint there is, and the default configuration contradicts itself.

`/etc/shadow` deliberately contains locked accounts (`*`) rather than password
hashes. A honeypot that hands out crackable hashes is publishing a credential
set that may well be reused on the real hosts the fake user names were modelled
on, and there is no analytical gain to offset that.

`/etc/motd` names a last-login date inside the deployment window. Update it if
you redeploy, or delete it - a motd claiming a date years in the past is itself
a tell.
