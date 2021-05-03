# Finding ID:	RHEL-07-040330
# Version:	RHEL-07-040330_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	There must be no .shosts files on the system.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040330' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

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
# Iterate locally-managed users to look for .shosts files
  {%- for userName in salt.user.list_users() %}
  {%- set userInfo = salt.user.info(userName) %}
  {%- set userHome = userInfo['home'] %}
  {%- set userShost = userHome + '/.shosts' %}
    {%- if salt.file.file_exists(userShost) %}
notify-{{ userName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''WARNING: User ''{{ userName }}'' has an ''.shosts'' file. Removing...''\n"'
    - cwd: /root
    - stateful: True
cmd_{{ stig_id }}-{{ userShost }}_remove:
  file.absent:
    - name: '{{ userShost }}'
    {%- else %}
notify-{{ userName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Info: User {{ userName }} does not have an .shosts file.''\n"'
    - cwd: /root
    - stateful: True
    {%- endif %}
  {%- endfor %}
{%- endif %}
