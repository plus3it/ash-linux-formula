# Finding ID:	RHEL-07-021060
# Version:	RHEL-07-021060_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The umask must be set to 077 for all local interactive user accounts.
#
# CCI-000368 
# CCI-000318 
# CCI-001812 
# CCI-001813 
# CCI-001814 
#    NIST SP 800-53 :: CM-6 c 
#    NIST SP 800-53A :: CM-6.1 (v) 
#    NIST SP 800-53 Revision 4 :: CM-6 c 
#    NIST SP 800-53 :: CM-3 e 
#    NIST SP 800-53A :: CM-3.1 (v) 
#    NIST SP 800-53 Revision 4 :: CM-3 f 
#    NIST SP 800-53 Revision 4 :: CM-11 (2) 
#    NIST SP 800-53 Revision 4 :: CM-5 (1) 
#    NIST SP 800-53 Revision 4 :: CM-5 (1) 
#
#################################################################
{%- set stig_id = 'RHEL-07-021060' %}
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
    - cwd: /root
    - stateful: True
{%- else %}
  {%- for user in userList %}
    {%- set userInfo = salt.user.info(user) %}
    {%- set userHome = userInfo['home'] %}
    {%- set userUid = userInfo['uid']|int %}
    {%- set userGid = userInfo['gid']|int %}
    {%- if userUid > sysuserMax %}
      {%- for shinitFile in shinitFiles%}
        {%- set fullPath = userHome + '/' + shinitFile %}
        {%- if salt.file.file_exists(fullPath) and
               salt.file.search(fullPath, 'umask') %}
fixown_{{ stig_id }}-{{ user }}-{{ shinitFile }}:
  file.replace:
    - name: '{{ userHome }}/{{ shinitFile }}'
    - pattern: '^[ 	]*umask .*$'
    - repl: 'umask 077'
        {%- endif  %}
      {%- endfor %}
    {%- endif  %}
  {%- endfor %}
{%- endif  %}
