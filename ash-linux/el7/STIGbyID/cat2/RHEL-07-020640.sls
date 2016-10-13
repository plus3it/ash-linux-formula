# Finding ID:	RHEL-07-020640
# Version:	RHEL-07-020640_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local interactive user home directories defined in the
#	/etc/passwd file must exist.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020640' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set sysuserMax = salt['cmd.run']("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs")|int %}
{%- set userList =  salt['user.list_users']() %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for user in userList %}
  {%- set userInfo = salt['user.info'](user) %}
  {%- set userHome = userInfo['home'] %}
  {%- set userUid = userInfo['uid']|int %}
  {%- set userGid = userInfo['gid']|int %}
  {%- if userUid > sysuserMax and 
         not (
              salt['file.directory_exists'](userHome) or
              salt['file.file_exists'](userHome)
             ) %}
notify_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'echo "{{ user }}''s home directory ''{{ userHome }}'' does not exist. Creating..."'
    - cwd: /root

createHome_{{ stig_id }}-{{ user }}:
  user.present:
    - name: '{{ user }}'
    - home: '{{ userHome }}'
    - createhome: True

fillHome_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'cd /etc/skel && find . -print | cpio -pmd {{ userHome }} > /dev/null 2>&1'
    - cwd: /root
    - require:
      - user: createHome_{{ stig_id }}-{{ user }}

fixHome_{{ stig_id }}-{{ user }}:
  file.directory:
    - name: '{{ userHome }}'
    - user: {{ userUid }}
    - group: {{ userGid }}
    - file_mode: '0600'
    - dir_mode: '0700'
    - recurse:
      - user
      - group
      - mode
    - require:
      - cmd: fillHome_{{ stig_id }}-{{ user }}

  {%- endif %}
{%- endfor %}
