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

include:
  - ash-linux.authconfig

{%- set stig_id = 'V38693' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set param_name = 'maxrepeat' %}
{%- set param_value = '3' %}
{%- set notify_change = 'Passwords'' repeating characters set to ' + param_value + ' (per STIG ID ' + stig_id + ').' %}
{%- set notify_nochange = 'Passwords'' repeating characters already capped at ' + param_value + ' (per STIG ID ' + stig_id + ').' %}

#define macro to set maxrepeat to '3'
{%- macro set_pam_param(stig_id, file, param, value, notify_text) %}
# Change existing {{ param }} to {{ value }}
replace_V{{ stig_id }}-{{ param }}:
  file.replace:
    - name: {{ file }}
    - pattern: '{{ param }}=[\S]*'
    - repl: '{{ param }}={{ value }}'
    - onlyif:
      - 'grep -E -e "[ \t]+{{ param }}=" {{ file }}'
      - 'test $(grep -c -E -e "[ \t]+{{ param }}={{ value }}[\s]+" {{ file }}) -eq 0'

# Tack on {{ param }} of {{ value }} if necessary
add_V{{ stig_id }}-{{ param }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>password[ \t]*requisite[ \t]*pam_cracklib.so.*$)'
    - repl: '\g<srctok> {{ param }}={{ value }}'
    - onlyif:
      - 'test $(grep -c -E -e "[ \t]+{{ param }}=" {{ file }}) -eq 0'

notify_V{{ stig_id }}-{{ param }}:
  cmd.run:
    - name: 'echo "{{ notify_text }}"'
{%- endmacro %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if not salt.file.file_exists(checkFile) %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_param(stig_id, checkFile, param_name, param_value, notify_change) }}

{%- elif not salt.file.search(checkFile, '[ \t]*' + param_name + '=' + param_value + '[\s]+') %}

#file {{ checkFile }} exists
#parameter {{ param_name }} not set, or not set correctly
#use macro to set {{ param_name }}
{{ set_pam_param(stig_id, checkFile, param_name, param_value, notify_change) }}

{%- else %}

#file {{ checkFile }} exists
#parameter {{ param_name }} already set to a negative value
notify_V{{ stig_id }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ notify_nochange }}"'

{%- endif %}
