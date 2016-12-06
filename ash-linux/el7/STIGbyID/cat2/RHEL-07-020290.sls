# Finding ID:	RHEL-07-020290
# Version:	RHEL-07-020290_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not have unnecessary accounts.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020290' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set userList =  salt.user.list_users() %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set bannedAccts = salt.pillar.get('ash-linux:lookup:banned-accts', [
                      'games',
                      'gopher'
                       ]) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
remove-user_{{ stig_id }}-NONE:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found no banned accounts to remove: state ok.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
  {%- for bannedAcct in bannedAccts %}
    {%- if bannedAcct in userList %}
remove-user_{{ stig_id }}-{{ bannedAcct }}:
  user.absent:
    - name: '{{ bannedAcct }}'
    {%- endif %}
  {%- endfor %}
{%- endif %}
