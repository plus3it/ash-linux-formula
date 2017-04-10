# Finding ID:	RHEL-07-021240
# Version:	RHEL-07-021240_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	A separate file system must be used for user home directories (such as /home or an equivalent).
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-021240' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs")|int %}
{%- set userList =  salt.user.list_users() %}
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
{%- set banMnt = [
                  '/',
                  '/boot',
                  '/tmp',
                  '/var',
                  '/var/log',
                  '/var/log/audit'
                   ] %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
  {%- for user in userList %}
    {%- set userAttribs = salt.user.info(user) %}
    {%- set userUid = userAttribs['uid'] %}
    {%- set userHome = userAttribs['home'] %}
    {%- set userShell = userAttribs['shell'] %}
    {%- if ( userUid >= sysuserMax ) and
           ( userShell in iShells ) %}
      {%- if salt.cmd.retcode('test -d ' + userHome) == 0 %}
        {%- set homeMount = salt['cmd.shell']('df --output=target ' + userHome + ' | tail -1') %}
        {%- if homeMount in banMnt %}
homedir_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''User {{ user }} home-directory is mounted on {{ homeMount }}: This will be a finding.''\n"'
    - cwd: /root
    - stateful: True  
        {%- else %}
homedir_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''User {{ user }} home-directory is mounted on {{ homeMount }}: state ok.''\n"'
    - cwd: /root
    - stateful: True  
        {%- endif %}
      {%- else %}
homedir_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''User {{ user }} home-directory does not exist.''\n"'
    - cwd: /root
    - stateful: True
      {%- endif %}
    {%- endif %}
  {%- endfor %}
{%- endif %}

## salt.user.info(root)
## {'fullname': 'root',
##  'gid': 0,
##  'groups': ['root'],
##  'home': '/root',
##  'homephone': '',
##  'name': 'root',
##  'passwd': 'x',
##  'roomnumber': '',
##  'shell': '/bin/bash',
##  'uid': 0,
##  'workphone': ''
## }

