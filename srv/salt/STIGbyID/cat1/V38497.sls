#!/bin/bash
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38497
# Finding ID: V-38497
# Version: RHEL-06-000030
#
#     If an account has an empty password, anyone could log in and run 
#     commands with the privileges of that account. Accounts with empty 
#     passwords should never be used in operational environments
#
#     If an account is configured for password authentication but does not 
#     have an assigned password, it may be possible to log into the account 
#     without authentication. Remove any instances of the "nullok" option 
#     in PAM subsystem
#
##########################################################################

script_V38497:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38497.sh

cmd_V38497-lnk:
  cmd.run:
  - name: 'test -L /etc/pam.d/system-auth'

cmd_V38497-sysauth:
  cmd.run:
  - name: 'sed -i -e "s/ nullok//" /etc/pam.d/system-auth'
  - onlyif: cmd_V38497-lnk

file_V38497-sysauth_ac:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: " nullok"
  - repl: ""

