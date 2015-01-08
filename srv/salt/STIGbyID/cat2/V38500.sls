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
check_V38500-{{ user }}:
  cmd.run:
  - name: 'printf "WARNING: Non-root user ''{{ user }}'' has userid ''{{ userId }}''.\n\t** MANUAL REMEDIATION REQUIRED: recommend reset to uid {{ noprivId }} **" ; exit 1'
    {% endif %}
  {% endif %}

{% endfor %}

######################################################################
# user.present(
#   name
#   uid=None			<= Change this (use system-supplied default)
#   gid=None			<= Preserve from current
#   gid_from_name=False		<= Pass as null
#   groups=None			<= Preserve from current
#   optional_groups=None	<= Preserve from current
#   remove_groups=True		<= Pass as null
#   home=None			<= Preserve from current
#   createhome=True		<= Pass as null
#   password=None		<= Preserve from current
#   enforce_password=True	<= Pass as null
#   empty_password=False	<= Pass as null
#   shell=None			<= Preserve from current
#   unique=True			<= Pass as null
#   system=False		<= Pass as null
#   fullname=None		<= Preserve from current
#   roomnumber=None		<= Preserve from current
#   workphone=None		<= Preserve from current
#   homephone=None		<= Preserve from current
#   loginclass=None		<= Preserve from current
#   date=None			<= Preserve from current
#   mindays=None		<= Preserve from current
#   maxdays=None		<= Preserve from current
#   inactdays=None		<= Preserve from current
#   warndays=None		<= Preserve from current
#   expire=None			<= Preserve from current
# )
######################################################################
