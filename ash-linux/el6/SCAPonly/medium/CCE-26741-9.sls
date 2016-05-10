# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26741-9
#
# Rule ID: accounts_password_reuse_limit
#
# Rule Summary: Limit Password Reuse
#
# Rule Text: Do not allow users to reuse recent passwords. The DoD and 
#            FISMA requirement is 24 passwords.  Preventing re-use of 
#            previous passwords helps ensure that a compromised password 
#            is not re-used by a user.
#
#################################################################

include:
  - ash-linux.authconfig

{%- set scapId = 'CCE-26741-9' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/medium/files' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set param_name = 'remember' %}
{%- set param_value = '24' %}
{%- set notify_change = 'Passwords'' reuse-interval set to ' + param_value + ' (per SCAP ID ' + scapId + ').' %}
{%- set notify_nochange = 'Passwords'' reuse-interval already set to ' + param_value + ' (per SCAP ID ' + scapId + ').' %}

#define macro to set 'remember' to '24'
{%- macro set_pam_param(scapId, file, param, value, notify_text) %}
# Change existing {{ param }} to {{ value }}
replace_{{ scapId }}-{{ param }}:
  file.replace:
    - name: {{ file }}
    - pattern: '{{ param }}=[\S]*'
    - repl: '{{ param }}={{ value }}'
    - onlyif:
      - 'grep -E -e "[ \t]+{{ param }}=" {{ file }}'
      - 'test $(grep -c -E -e "[ \t]+{{ param }}={{ value }}[\s]+" {{ file }}) -eq 0'

# Tack on {{ param }} of {{ value }} if necessary
add_{{ scapId }}-{{ param }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>password[ \t]*requisite[ \t]*pam_cracklib.so.*$)'
    - repl: '\g<srctok> {{ param }}={{ value }}'
    - onlyif:
      - 'test $(grep -c -E -e "[ \t]+{{ param }}=" {{ file }}) -eq 0'

notify_{{ scapId }}-{{ param }}:
  cmd.run:
    - name: 'echo "{{ notify_text }}"'
{%- endmacro %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

{%- if not salt['file.file_exists'](checkFile) %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_param(scapId, checkFile, param_name, param_value, notify_change) }}

{%- elif not salt['file.search'](checkFile, '[ \t]*' + param_name + '=' + param_value + '[\s]+') %}

#file {{ checkFile }} exists
#parameter {{ param_name }} not set, or not set correctly
#use macro to set {{ param_name }}
{{ set_pam_param(scapId, checkFile, param_name, param_value, notify_change) }}

{%- else %}

#file {{ checkFile }} exists
#parameter {{ param_name }} already set to a negative value
notify_{{ scapId }}-{{ param_name }}:
  cmd.run:
    - name: 'echo "{{ notify_nochange }}"'

{%- endif %}
