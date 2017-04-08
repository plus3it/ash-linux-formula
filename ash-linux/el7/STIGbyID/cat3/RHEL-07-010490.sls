# Finding ID:	RHEL-07-010490
# Version:	RHEL-07-010490_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	Unnecessary default system accounts must be removed.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-010490' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs")|int %}
{%- set userList =  salt.user.list_users() %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set bannedAccts = salt.pillar.get('ash-linux:lookup:banned-accts', [
                      'games',
                      'ftp'
                       ]) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
  {%- for bannedAcct in bannedAccts %}
    {%- if bannedAcct in userList %}
remove-user_{{ stig_id }}-{{ bannedAcct }}:
  user.absent:
    - name: '{{ bannedAcct }}'
    {%- endif %}
  {%- endfor %}
{%- endif %}
