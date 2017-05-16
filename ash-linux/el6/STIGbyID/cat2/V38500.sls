# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38500
# Finding ID:	V-38500
# Version:	RHEL-06-000032
# Finding Level:	Medium
#
#     The root account must be the only account having a UID of 0. An
#     account has root authority if it has a UID of 0. Multiple accounts
#     with a UID of 0 afford more opportunity for potential intruders to
#     guess a password for a privileged account. Proper ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38500' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

# Get userid of the "nobody" user
{%- set noprivInfo = salt['user.info']('nobody') %}
{%- set noprivId = noprivInfo['uid'] %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- for user in salt.ash.shadow_list_users() %}
  {%- set userInfo = salt.user.info(user) %}
  {%- set userId = userInfo['uid'] %}
  {%- if userId == 0 %}
    #########################################
    # If the user is "root", just acknowledge
    {%- if user == 'root' %}
notify_{{ stigId }}-{{ user }}:
  cmd.run:
    - name: 'echo "Info: User ''{{ user }}'' has userid ''{{ userId }}''"'

    #################################################################
    # If the uid '0' account isn't "root", nuke and recreate as non-0
    {%- else %}
    {%- set userShadow = salt['shadow.info'](user) %}
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

notify_{{ stigId }}-{{ user }}:
  cmd.run:
    - name: 'printf "WARNING: Non-root user ''{{ user }}'' has userid ''{{ userId }}''.\n\t** Automatic remediation will be attempted **\n\n\tNote:\n\t* First free, non-privileged UID will be allocated;\n\t* Secondary groups may be lost;\n\t* Account expiry info may be altered\n"'

update_{{ stigId }}-{{ user }}_nuke:
  user.absent:
    - name: '{{ userName }}'
    - force: 'True'

update_{{ stigId }}-{{ user }}_recreate:
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

update_{{ stigId }}-{{ user }}_chown:
  cmd.run:
    - name: 'echo "Chowning {{ userName }}''s home directory" ; chown -R {{ userName }} {{ userHome }}'
    {%- endif %}
  {%- endif %}

{%- endfor %}
