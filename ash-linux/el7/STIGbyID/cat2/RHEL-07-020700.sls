# Finding ID:	RHEL-07-020700
# Version:	RHEL-07-020700_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories contained in local interactive user
#	home directories must have mode 0750 or less permissive.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020700' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set sysuserMax = salt.cmd.run("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs")|int %}
{%- set userList =  salt.user.list_users() %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for user in userList %}
  {%- set userInfo = salt.user.info(user) %}
  {%- set userHome = userInfo['home'] %}
  {%- set userUid = userInfo['uid']|int %}
  {%- if userUid > sysuserMax %}
strip_{{ stig_id }}-{{ userHome }}:
  cmd.script:
    - name: '{{ stig_id }}_helper.sh "{{ userHome }}"'
    - source: salt://{{ helperLoc }}/{{ stig_id }}_helper.sh
    - cwd: /root
    - stateful: True

  {%- endif %}
{%- endfor %}

