# Finding ID:	RHEL-07-020850
# Version:	RHEL-07-020850_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	Local initialization files for local interactive users must be
#	group-owned by the users primary group or root.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020850' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs")|int %}
{%- set userList =  salt.user.list_users() %}
{%- set shinitFiles = [
                       '.bash_login',
                       '.bash_profile',
                       '.bashrc',
                       '.cshrc',
                       '.kshrc',
                       '.login',
                       '.profile',
                       '.tcshrc',
                       '.zlogin',
                       '.zprofile',
                       '.zshrc'
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
  {%- for user in userList %}
    {%- set userInfo = salt.user.info(user) %}
    {%- set userHome = userInfo['home'] %}
    {%- set userUid = userInfo['uid']|int %}
    {%- set userGid = userInfo['gid']|string %}
    {%- set gidmap = 'getent group ' + userGid + ' | cut -d : -f 1' %}
    {%- set userGroup = salt['cmd.shell'](gidmap)|string %}
    {%- if userUid > sysuserMax %}
      {%- for shinitFile in shinitFiles%}
        {%- if salt.file.file_exists(userHome + '/' + shinitFile) %}
fixown_{{ stig_id }}-{{ user }}-{{ shinitFile }}:
  file.managed:
    - name: '{{ userHome }}/{{ shinitFile }}'
    - group: '{{ userGroup }}'
    - replace: False
        {%- endif  %}
      {%- endfor %}
    {%- endif  %}
  {%- endfor %}
{%- endif %}
