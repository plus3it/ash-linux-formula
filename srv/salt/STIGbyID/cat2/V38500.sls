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

# Get userid of the "nobody" user
{% set noprivInfo = salt['user.info']('nobody') %}
{% set noprivId = noprivInfo['uid'] %}

{% for user in salt['user.list_users']() %}
  {% set userInfo = salt['user.info'](user) %}
  {% set userId = userInfo['uid'] %}
  {% if userId == 0 %}
    {% if user == 'root' %}
check_V38500-{{ user }}:
  cmd.run:
  - name: 'echo "Info: User ''{{ user }}'' has userid ''{{ userId }}''"'
    {% else %}
    {% set userShadow = salt['shadow.info'](user) %}
    {% set userDate = userShadow['lstchg'] %}
    {% set userExpire = userShadow['expire'] %}
    {% set userFullname = userInfo['fullname'] %}
    {% set userGid = userInfo['gid'] %}
    {% set userHome = userInfo['home'] %}
    {% set userHomePhone = userInfo['homephone'] %}
    {% set userInactiv = userShadow['inact'] %}
    {% set userMaxDay = userShadow['max'] %}
    {% set userMinDay = userShadow['min'] %}
    {% set userName = user %}
    {% set userPasswd = userShadow['passwd'] %}
    {% set userRoomNo = userInfo['roomnumber'] %}
    {% set userShell = userInfo['shell'] %}
    {% set userWarnDay = userShadow['warn'] %}
    {% set userWorkPhone = userInfo['workphone'] %}

check_V38500-{{ user }}:
  cmd.run:
  - name: 'printf "WARNING: Non-root user ''{{ user }}'' has userid ''{{ userId }}''.\n\t** Automatic remediation will be attempted **\n\n\tNote:\n\t* Secondary groups may be lost;\n\t* Account expiry info may be altered\n"'

update_V38500-{{ user }}_nuke:
  user.absent:
  - name: '{{ userName }}'
  - force: 'True'
update_V38500-{{ user }}_recreate:
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
    {% endif %}
  {% endif %}

{% endfor %}
