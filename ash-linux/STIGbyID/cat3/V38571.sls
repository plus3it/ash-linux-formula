# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38571
# Finding ID:	V-38571
# Version:	RHEL-06-000059
# Finding Level:	Low
#
#     The system must require passwords to contain at least one lowercase 
#     alphabetic character. Requiring a minimum number of lowercase 
#     characters makes password guessing attacks more difficult by ensuring 
#     a larger search space.
#
#  CCI: CCI-000193
#  NIST SP 800-53 :: IA-5 (1) (a)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
############################################################

script_V38571-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38571.sh

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'lcredit' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38571-linkSysauth:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search'](checkFile, ' pam_cracklib.so ') %}
  {% if salt['file.search'](checkFile, ' ' + parmName + '=-[0-9][0-9]*[ ]*') %}
lcredit_V38571-minusOne:
  cmd.run:
    - name: 'echo "Passwords already require at least one lowercase letter"'
  {% elif salt['file.search'](checkFile, ' ' + parmName + '=[0-9][0-9]*[ ]*') %}
# Change existing lcredit with positive integer value to minus-1
lcredit_V38571-minusOne:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '{{ parmName }}=[0-9][0-9]*'
    - repl: '{{ parmName }}=-1'
  {% else %}
# Tack on decredit of minus-1 if necessary
lcredit_V38571-minusOne:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>password[ 	]*requisite[ 	]*pam_cracklib.so.*$)'
    - repl: '\g<srctok> {{ parmName }}=-1'
  {% endif %}
{% endif %}
