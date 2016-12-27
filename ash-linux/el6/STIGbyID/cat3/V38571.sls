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

include:
  - ash-linux.authconfig

{%- set stig_id = '38571' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set param_name = 'lcredit' %}
{%- set param_value = '-1' %}
{%- set notify_change = 'Forced passwords to require at least one lowercase letter.' %}
{%- set notify_nochange = 'Passwords already require at least one lowercase letter.' %}

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

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- if not salt.file.file_exists(checkFile) %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_param(stig_id, checkFile, param_name, param_value, notify_change) }}

{%- elif not salt.file.search(checkFile, '[ \t]+' + param_name + '=-[1-9]+[\s]+') %}

#file {{ checkFile }} exists
#parameter {{ param_name }} not set, or not set correctly
#use macro to set the parameter
{{ set_pam_param(stig_id, checkFile, param_name, param_value, notify_change) }}

{%- else %}

#file {{ checkFile }} exists
#parameter {{ param_name }} already set to a negative value
notify_V{{ stig_id }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ notify_nochange }}"'

{%- endif %}
