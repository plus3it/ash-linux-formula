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

include:
  - ash-linux.authconfig

{%- set stig_id = '38482' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set param_name = 'dcredit' %}
{%- set param_value = '-1' %}

{%- macro set_pam_param(stig_id, file, param, value) %}
# Change existing {{ param_name }} with positive integer value to minus-1
replace_dcredit_V{{ stig_id }}-minusOne:
  file.replace:
    - name: {{ file }}
    - pattern: '{{ param }}=[0-9][0-9]*'
    - repl: '{{ param }}={{ value }}'
    - onlyif:
      - 'grep -E -e " {{ param }}=[0-9][0-9]*[ ]*" {{ file }}'

# Tack on {{ param }} of minus-1 if necessary
add_dcredit_V{{ stig_id }}-minusOne:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>password[ \t]*requisite[ \t]*pam_cracklib.so.*$)'
    - repl: '\g<srctok> {{ param }}={{ value }}'
    - onlyif:
      - 'grep -v -E -e " {{ param }}=[0-9][0-9]*[ ]*" {{ file }}'

notify_V{{ stig_id }}-minusOne:
  cmd.run:
    - name: 'echo "Forced passwords to require at least one digit."'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh

{%- if salt['file.file_exists'](checkFile) %}

#file {{ checkFile }} exists

  {%- if salt['file.search'](checkFile, ' ' + param_name + '=-[0-9][0-9]*[ ]*') %}

notify_V{{ stig_id }}-minusOne:
  cmd.run:
    - name: 'echo "Passwords already require at least one digit"'

  {%- else %}

#Passwords not yet set to require one digit
#use macro to set the parameter
{{ set_pam_param(stig_id, checkFile, param_name, param_value) }}

  {%- endif %}

{%- else %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_param(stig_id, checkFile, param_name, param_value) }}

{%- endif %}