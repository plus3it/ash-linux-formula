# STIG URL:
# Finding ID:	RHEL-07-040300
# Version:	RHEL-07-040300_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must display the date and time of the last successful 
#     account logon upon a SSH (or other remote access method) logon.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

include:
  - ash-linux.authconfig

{%- set stig_id = 'RHEL-07-040300' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set pamFile = '/etc/pam.d/system-auth-ac' %}
{%- set pamMod = 'pam_lastlog.so' %}
{%- set failNotice = 'session     required      pam_lastlog.so showfailed' %}

{%- macro set_pam_rule(stig_id, file, module, rule) %}
update_{{ stig_id }}-{{ module }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(session[ \t]*.*{{ module }}[ \t]*[\S]*)'
    - repl: '{{ rule }}'
    - onlyif:
      - 'grep -E -e "{{ module }}" {{ file }}'
      - 'test $(grep -c -E -e "{{ module }} showfailed" {{ file }}) -eq 0'

add_{{ stig_id }}-{{ module }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>session[ \t]*.*pam_limits.so.*$)'
    - repl: '\g<srctok>\n{{ rule }}'
    - onlyif:
      - 'test $(grep -c -E -e "{{ module }}" {{ file }}) -eq 0'

notify_{{ stig_id }}-{{ module }}:
  cmd.run:
    - name: 'printf "Adding {{ module }} with ''showfailed'' option in {{ file }}\n"'
{%- endmacro %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

{%- if not salt['file.file_exists'](pamFile) %}
#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_rule(stig_id, pamFile, pamMod, failNotice) }}

{%- elif not salt['file.search'](pamFile, pamMod + ' showfailed') %}

#file {{ pamMod }} exists
#{{ pamMod }} showfailed is not present
#use macro to set the parameter
{{ set_pam_rule(stig_id, pamFile, pamMod, failNotice) }}

{%- else %}

#file {{ pamMod }} exists
#{{ pamMod }} showfailed already present
notify_{{ stig_id }}-{{ pamMod }}:
  cmd.run:
    - name: 'printf "{{ pamMod }} already configured for ''showfailed'' in {{ pamFile }}\n"'

{%- endif %}
