# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38693
# Finding ID:	V-38693
# Version:	RHEL-06-000299
# Finding Level:	Low
#
#     The system must require passwords to contain no more than three 
#     consecutive repeating characters. Passwords with excessive repeating 
#     characters may be more vulnerable to password-guessing attacks.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38693-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38693.sh

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'maxrepeat' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38693-linkSysauth:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
{% endif %}

# Check if pam_cracklib is configured for use...
{% if salt['file.search'](checkFile, ' pam_cracklib.so ') %}
  # ...and maxrepeat is defined at '3'
  {% if salt['file.search'](checkFile, ' ' + parmName + '=3[ ]*') %}
maxrepeat_V38693-setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters already capped at ''3''"'
  # Change existing positive maxrepeat value to 3
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=[0-9][0-9]*[ ]*') %}
maxrepeat_V38693-setThree:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '{{ parmName }}=[0-9][0-9]*'
    - repl: '{{ parmName }}=3'
  # Change existing negative maxrepeat value to 3
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=-[0-9][0-9]*[ ]*') %}
maxrepeat_V38693-setThree:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '{{ parmName }}=-[0-9][0-9]*'
    - repl: '{{ parmName }}=3'
  {% else %}
# Tack on maxrepeat of '3' if necessary
maxrepeat_V38693-setThree:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
    - repl: '\g<srctok> {{ parmName }}=3'
  {% endif %}
{% endif %}
