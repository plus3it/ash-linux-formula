# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51875
# Finding ID:	V-51875
# Version:	RHEL-06-000372
# Finding Level:        Medium
#
#     Users need to be aware of activity that occurs regarding their 
#     account. Providing users with information regarding the number 
#     of unsuccessful attempts that were made to login to their 
#     account allows the user to determine if any unauthorized 
#     activity has occurred and gives them an opportunity to notify 
#     administrators. 
#
# CCI: CCI-000366
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

script_V51875-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V51875.sh

# Ensure that authconfig has been run prior to trying to update the PAM files
cmd_V51875-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
  - unless: 'test -f /etc/pam.d/system-auth-ac'

{% set pamFile = '/etc/pam.d/system-auth-ac' %}
{% set pamMod = 'pam_lastlog.so' %}
{% set failNotice = 'session	required	pam_lastlog.so showfailed' %}

{% if salt['file.search'](pamFile, pamMod) %}
notify_V51875-{{ pamFile }}:
  cmd.run:
  - name: 'printf "{{ pamMod }} already configured for ''showfailed'' in {{ pamFile }}\n"'
{% endif %}
############################################################
{% else %}
insert_V38501-{{ checkFile }}_faillock:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '^(?P<srctok>auth[ 	]*[a-z]*[ 	]*pam_limits.so.*$)'
  - repl: '\g<srctok>\n{{ failNotice }}'
  {% endif %}
{% endfor %}
