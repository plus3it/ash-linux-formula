#!/bin/sh
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38497
# Finding ID:	V-38497
# Version:	RHEL-06-000030
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

include:
  - ash-linux.authconfig

{%- set stig_id = '38497' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

file_V{{ stig_id }}-sysauth_ac:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '[	 ]*nullok[	 ]*'
    - repl: ' '
    - onlyif: 
      - 'test -f {{ checkFile }}'
