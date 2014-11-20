# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38569
# Finding ID:	V-38569
# Version:	RHEL-06-000057
# Finding Level:	Low
#
#     The system must require passwords to contain at least one uppercase 
#     alphabetic character. Requiring a minimum number of uppercase 
#     characters makes password guessing attacks more difficult by ensuring 
#     a larger search space.
#
############################################################

script_V38569-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38569.sh

{% if not salt['file.file_exists']('/etc/pam.d/system-auth-ac') %}
cmd_V38569-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search']('/etc/pam.d/system-auth-ac', ' pam_cracklib.so ') %}
  {% if salt['file.search']('/etc/pam.d/system-auth-ac', ' ucredit=[0-9][0-9]*[ ]*') %}
# Change existing ucredit with positive integer value to minus-1
ucredit_V38569-minusOne:
  file.replace:
  - name: /etc/pam.d/system-auth-ac
  - pattern: 'ucredit=[0-9][0-9]*'
  - repl: 'ucredit=-1'
  {% elif salt['file.search']('/etc/pam.d/system-auth-ac', ' ucredit=-[0-9][0-9]*[ ]*') %}
ucredit_V38569-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one uppercase letter"'
  {% else %}
# Tack on decredit of minus-1 if necessary
ucredit_V38569-minusOne:
  file.replace:
  - name: '/etc/pam.d/system-auth-ac'
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> ucredit=-1'
  {% endif %}
{% endif %}


