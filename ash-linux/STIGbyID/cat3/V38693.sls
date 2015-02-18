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

{% set stig_id = '38693' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh

{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'maxrepeat' %}

{% if salt['file.file_exists'](checkFile) %}
#system-auth-ac exists
  {% if not salt['cmd.run']('grep -c -E -e "[ \t]' + parmName + '=3[ \t]*" ' + checkFile ) == '0' %}
#maxrepeat already set to 3
notify_V{{ stig_id }}-maxrepeat_setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters already capped at ''3'' (per STIG ID V-{{ stig_id }})"'
  {% else %}
#maxrepeat not yet set to 3; add the parameter, or update it if the parameter is set to a bad value
maxrepeat_V{{ stig_id }}-setThree:
  file.replace:
    - name : {{ checkFile }}
    - pattern: '{{ parmName }}=[-]?[\S]*'
    - repl: '{{ parmName }}=3'
maxrepeat_add_V{{ stig_id }}-setThree:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<tok_pass>password[ \t]*.*pam_cracklib.so.*)'
    - repl: '\g<tok_pass> {{ parmName }}=3'
    - onlyif: 
      - 'test $(grep -c -E -e "pam_cracklib.so.*maxrepeat.*" {{ checkFile }}) -eq 0'
notify_V{{ stig_id }}-maxrepeat_setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters set to ''3'' (per STIG ID V-{{ stig_id }})"'
  {% endif %}
{% else %}
#system-auth-ac does not exist; make sure authconfig is installed and run authconfig --update
pkg_V{{ stig_id }}:
  pkg.installed:
    - name: authconfig
cmd_V{{ stig_id }}-linkSysauth:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
    - require:
      - pkg: pkg_V{{ stig_id }}
#set maxrepeat to 3
maxrepeat_V{{ stig_id }}-setThree:
  file.replace:
    - name : {{ checkFile }}
    - pattern: '{{ parmName }}=[-]?[\S]*'
    - repl: '{{ parmName }}=3'
maxrepeat_add_V{{ stig_id }}-setThree:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<tok_pass>password[ \t]*.*pam_cracklib.so.*)'
    - repl: '\g<tok_pass> {{ parmName }}=3'
    - onlyif: 
      - 'test $(grep -c -E -e "pam_cracklib.so.*maxrepeat.*" {{ checkFile }}) -eq 0'
notify_V{{ stig_id }}-maxrepeat_setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters set to ''3'' (per STIG ID V-{{ stig_id }})"'
{% endif %}
