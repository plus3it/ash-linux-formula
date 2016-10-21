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
{%- set userList =  salt['user.list_users']() %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for user in userList %}
  {%- set userInfo = salt['user.info'](user) %}
  {%- set userHome = userInfo['home'] %}
  {%- if not (
              salt['file.directory_exists'](userHome) or
              salt['file.file_exists'](userHome)
             ) %}
notify_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'echo "{{ user }}''s home directory ''{{ userHome }}'' does not exist."'
    - cwd: /root
  {%- endif %}
{%- endfor %}
