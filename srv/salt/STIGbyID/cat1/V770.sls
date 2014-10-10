# STIG URL: http://www.stigviewer.com/stig/unix_srg/2013-03-26/finding/V-770
# Finding ID: V-770
# Version: GEN000560
#
#     The SA will ensure each account in the /etc/passwd file has a 
#     password assigned or is disabled in the password, shadow, or 
#     equivalent, file by disabling the password and/or by assigning a 
#     false shell in the password file.
#
##########################################################################

cmd_V770-find:
  cmd.run:
  - name: 'printf "Found users with null passwords:\n"; printf "\t%s\n" `cut -d ":" -f 1,2 /etc/shadow | egrep ":$" | cut -d ":" -f 1` | tee /tmp/nullpass'
  - onlyif: 'cut -d ":" -f 1,2 /etc/shadow | egrep ":$"'

cmd_V770-fix:
  cmd.run:
  - name: 'for user in `cat /tmp/nullpass`; do passwd -l $user; done'
  - unless: cmd_V770-find


