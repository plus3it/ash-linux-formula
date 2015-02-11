# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38570
# Finding ID:	V-38570
# Version:	RHEL-06-000058
# Finding Level:	Low
#
#     The system must require passwords to contain at least one special 
#     character. Requiring a minimum number of special characters makes 
#     password guessing attacks more difficult by ensuring a larger search 
#     space.
#
############################################################

script_V38570-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38570.sh

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'ocredit' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38570-linkSysauth:
  cmd.run:
  - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search'](checkFile, ' pam_cracklib.so ') %}
  {% if salt['file.search'](checkFile, ' ' + parmName + '=[0-9][0-9]*[ ]*') %}
# Change existing ocredit with positive integer value to minus-1
ocredit_V38570-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '{{ parmName }}=[0-9][0-9]*'
  - repl: '{{ parmName }}=-1'
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=-[0-9][0-9]*[ ]*') %}
ocredit_V38570-minusOne:
  cmd.run:
  - name: 'echo "Passwords already require at least one special character"'
  {% else %}
# Tack on ocredit of minus-1 if necessary
ocredit_V38570-minusOne:
  file.replace:
  - name: {{ checkFile }}
  - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
  - repl: '\g<srctok> {{ parmName }}=-1'
  {% endif %}
{% endif %}
