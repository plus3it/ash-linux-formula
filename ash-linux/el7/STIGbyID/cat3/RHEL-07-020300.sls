# Finding ID:	RHEL-07-020300
# Version:	RHEL-07-020300_rule
# SRG ID:	SRG-OS-000104-GPOS-00051
# Finding Level:	low
# 
# Rule Summary:
#	All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.
#
# CCI-000764 
#    NIST SP 800-53 :: IA-2 
#    NIST SP 800-53A :: IA-2.1 
#    NIST SP 800-53 Revision 4 :: IA-2 
#
#################################################################
{%- set stig_id = 'RHEL-07-020300' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set userList =  salt.user.list_users() %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
  {%- for user in userList %}
    {%- set gid = salt.user.info(user)['gid'] %}
    {%- if not salt['cmd.shell']('grep :' + gid|string  + ': /etc/group') %}
test_{{ stig_id }}-{{ user }}:
  group.present:
    - name: 'stig_{{ user }}'
    - gid: {{ gid }}
    {%- endif %}
  {%- endfor %}
{%- endif %}


## {'local': {'fullname': 'root',
##            'gid': 0,
##            'groups': ['root'],
##            'home': '/root',
##            'homephone': '',
##            'name': 'root',
##            'passwd': 'x',
##            'roomnumber': '',
##            'shell': '/bin/bash',
##            'uid': 0,
##            'workphone': ''}}
