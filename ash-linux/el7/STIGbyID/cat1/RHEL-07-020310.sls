# Finding ID:	RHEL-07-020310
# Version:	RHEL-07-020310_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The root account must be the only account having
#	unrestricted access to the system.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020310' %}
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
# Get userid of the "nobody" user
  {%- set noprivInfo = salt.user.info('nobody') %}
  {%- set noprivId = noprivInfo['uid'] %}

  {%- for user in salt.user.list_users() %}
    {%- set userInfo = salt.user.info(user) %}
    {%- set userId = userInfo['uid'] %}
    {%- if userId == 0 %}
    #########################################
    # If the user is "root", just acknowledge
      {%- if user == 'root' %}
notify_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Info: User {{ user }} has userid {{ userId }}.''\n"'
    - cwd: /root
    - stateful: True

    #################################################################
    # If the uid '0' account isn't "root", nuke and recreate as non-0
      {%- else %}
      {%- set userShadow = salt.shadow.info(user) %}
      {%- set userDate = userShadow['lstchg'] %}
      {%- set userExpire = userShadow['expire'] %}
      {%- set userFullname = userInfo['fullname'] %}
      {%- set userGid = userInfo['gid'] %}
      {%- set userHome = userInfo['home'] %}
      {%- set userHomePhone = userInfo['homephone'] %}
      {%- set userInactiv = userShadow['inact'] %}
      {%- set userMaxDay = userShadow['max'] %}
      {%- set userMinDay = userShadow['min'] %}
      {%- set userName = user %}
      {%- set userPasswd = userShadow['passwd'] %}
      {%- set userRoomNo = userInfo['roomnumber'] %}
      {%- set userShell = userInfo['shell'] %}
      {%- set userWarnDay = userShadow['warn'] %}
      {%- set userWorkPhone = userInfo['workphone'] %}

notify_{{ stig_id }}-{{ user }}:
  cmd.run:
    - name: 'printf "WARNING: Non-root user ''{{ user }}'' has userid ''{{ userId }}''.\n\t** Automatic remediation will be attempted **\n\n\tNote:\n\t* First free, non-privileged UID will be allocated;\n\t* Secondary groups may be lost;\n\t* Account expiry info may be altered\n"'

update_{{ stig_id }}-{{ user }}_nuke:
  user.absent:
    - name: '{{ userName }}'
    - force: 'True'

update_{{ stig_id }}-{{ user }}_recreate:
  user.present:
    - name: '{{ userName }}'
    - gid: '{{ userGid }}'
    - home: '{{ userHome }}'
    - password: '{{ userPasswd }}'
    - shell: '{{ userShell }}'
    - fullname: '{{ userFullname }}'
    - roomnumber: '{{ userRoomNo }}'
    - workphone: '{{ userWorkPhone }}'
    - homephone: '{{ userHomePhone }}'
    - date: '{{ userDate }}'
    - mindays: '{{ userMinDay }}'
    - maxdays: '{{ userMaxDay }}'
    - inactdays: '{{ userInactiv }}'
    - warndays: '{{ userWarnDay }}'
    - expire: '{{ userExpire }}'

update_{{ stig_id }}-{{ user }}_chown:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Chowning {{ userName }}`s home directory" ; chown -R {{ userName }} {{ userHome }}''\n"'
    - cwd: /root
    - stateful: True
      {%- endif %}
    {%- endif %}

  {%- endfor %}
{%- endif %}
