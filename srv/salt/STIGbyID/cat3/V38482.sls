# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38482
# Finding ID:	V-38482
# Version:	RHEL-06-000056
# Finding Level:	Low
#
#     The system must require passwords to contain at least one numeric 
#     character. Requiring digits makes password guessing attacks more 
#     difficult by ensuring a larger search space.
#
############################################################

script_V38482-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38482.sh

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'dcredit' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38482-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search'](checkFile, ' pam_cracklib.so ') %}
  {% if salt['file.search'](checkFile, ' ' + parmName + '=[0-9][0-9]*[ ]*') %}
# Change existing dcredit with positive integer value to minus-1
dcredit_V38482-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '{{ parmName }}=[0-9][0-9]*'
  - repl: '{{ parmName }}=-1'
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=-[0-9][0-9]*[ ]*') %}
dcredit_V38482-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one digit"'
  {% else %}
# Tack on decredit of minus-1 if necessary
dcredit_V38482-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> {{ parmName }}=-1'
  {% endif %}
{% endif %}


