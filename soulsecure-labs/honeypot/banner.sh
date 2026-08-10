#!/bin/sh
# Deliberate false lead: vsFTPd 2.3.4 is a famous banner (real CVE-2011-2523
# backdoor) that gets a lot of students excited. This one is just a banner --
# no FTP protocol behind it, no flag here. The lesson: a scary-looking banner
# is a lead to verify, not a finding to report on its own.
printf '220 (vsFTPd 2.3.4)\r\n'
