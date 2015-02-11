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

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'ucredit' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38569-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search'](checkFile, ' pam_cracklib.so ') %}
  {% if salt['file.search'](checkFile, ' ' + parmName + '=[0-9][0-9]*[ ]*') %}
# Change existing ucredit with positive integer value to minus-1
ucredit_V38569-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '{{ parmName }}=[0-9][0-9]*'
  - repl: '{{ parmName }}=-1'
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=-[0-9][0-9]*[ ]*') %}
ucredit_V38569-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one uppercase letter"'
  {% else %}
# Tack on ucredit value of minus-1 if necessary
ucredit_V38569-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> {{ parmName }}=-1'
  {% endif %}
{% endif %}
