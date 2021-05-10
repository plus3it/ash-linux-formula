# Finding ID:	RHEL-07-020880
# Version:	RHEL-07-020880_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	Local initialization files must not execute world-writable programs.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020880' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs
")|int %}
{%- set userList = salt.user.list_users() %}
{%- set iShells = [
                   '/bin/sh',
                   '/bin/bash',
                   '/bin/csh',
                   '/bin/ksh',
                   '/bin/mksh',
                   '/bin/tcsh',
                   '/bin/zsh',
                   '/usr/bin/sh',
                   '/usr/bin/bash',
                   '/usr/bin/csh',
                   '/usr/bin/ksh',
                   '/usr/bin/mksh',
                   '/usr/bin/tcsh',
                   '/usr/bin/zsh'
                    ] %}
{%- set oWrite = salt['cmd.shell']('find / \( -name sys -o -name proc \) -prune -o  -perm -002 -type f -print').split('\n') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root


# Matching process
#   1) Find all globally-writeable files
#   2) Get list of accounts to check:
#      a. Get list of all local users
#      b. Filter out userids < SYS_UID_MAX
#      c. Filter out userids w/o interactive shell
#   3) Search user's dot-files references to globally-writeable
#      files. If found, change mode on globally-writeable file
#      to 0755.


{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Iterate local user-list
  {%- for user in userList %}
    {%- set uinfo = salt.user.info(user) %}
  # Regular interactive-users will have UID > SYS_USER_MAX and
  # will have an interactive shell assigned.
    {%- if ( uinfo['uid'] > sysuserMax ) and
         ( uinfo['shell'] in iShells ) %}
      {%- set uhome = uinfo['home'] %}
      {%- set dotfiles = salt.file.find(uhome, name='.*', type='f', maxdepth=1) %}
      {%- for dotfile in dotfiles %}
        {%- for chkFile in oWrite %}
          {%- if chkFile and salt.file.search(dotfile, chkFile) %}
fixperm_{{ stig_id }}-{{ chkFile }}:
  cmd.run:
    - name: 'chmod o-w "{{ chkFile }}" && printf "\nchanged=yes comment=''found {{ chkFile }} referenced in {{ dotfile }}: stripping global-write perms.''\n"'
    - cwd: /root
    - stateful: True
          {%- endif %}
        {%- endfor %}
      {%- endfor %}
    {%- endif %}
  {%- endfor %}
{%- endif %}
