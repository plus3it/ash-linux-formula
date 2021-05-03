# Finding ID:	RHEL-07-020620
# Version:	RHEL-07-020620_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	All local interactive users must have a home directory assigned
#	in the /etc/passwd file.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020620' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs")|int %}
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


script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

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
      {%- if salt.file.directory_exists(uhome) %}
mkdir_{{ stig_id }}-{{ uhome }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ user }} has home directory: state ok.''\n"'
    - cwd: /root
    - stateful: True
      {%- else %}
        {%- set ugroup = salt.user.primary_group(user) %}
mkdir_{{ stig_id }}-{{ uhome }}:
  file.directory:
    - name: '{{ uhome }}'
    - user: '{{ user }}'
    - group: '{{ ugroup }}'
    - mode: '0700'
      {%- endif %}
    {%- endif %}
  {%- endfor %}
{%- endif %}
