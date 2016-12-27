# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51875
# Finding ID:	V-51875
# Version:	RHEL-06-000372
# Finding Level:        Medium
#
#     Users need to be aware of activity that occurs regarding their 
#     account. Providing users with information regarding the number 
#     of unsuccessful attempts that were made to login to their 
#     account allows the user to determine if any unauthorized 
#     activity has occurred and gives them an opportunity to notify 
#     administrators. 
#
# CCI: CCI-000366
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

include:
  - ash-linux.authconfig

{%- set stig_id = '51875' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set pamFile = '/etc/pam.d/system-auth-ac' %}
{%- set pamMod = 'pam_lastlog.so' %}
{%- set failNotice = 'session     required      pam_lastlog.so showfailed' %}

{%- macro set_pam_rule(stig_id, file, module, rule) %}
update_V{{ stig_id }}-{{ module }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(session[ \t]*.*{{ module }}[ \t]*[\S]*)'
    - repl: '{{ rule }}'
    - onlyif:
      - 'grep -E -e "{{ module }}" {{ file }}'
      - 'test $(grep -c -E -e "{{ module }} showfailed" {{ file }}) -eq 0'

add_V{{ stig_id }}-{{ module }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>session[ \t]*.*pam_limits.so.*$)'
    - repl: '\g<srctok>\n{{ rule }}'
    - onlyif:
      - 'test $(grep -c -E -e "{{ module }}" {{ file }}) -eq 0'

notify_V{{ stig_id }}-{{ module }}:
  cmd.run:
    - name: 'printf "Adding {{ module }} with ''showfailed'' option in {{ file }}\n"'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

{%- if not salt.file.file_exists(pamFile) %}
#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ set_pam_rule(stig_id, pamFile, pamMod, failNotice) }}

{%- elif not salt.file.search(pamFile, pamMod + ' showfailed') %}

#file {{ pamMod }} exists
#{{ pamMod }} showfailed is not present
#use macro to set the parameter
{{ set_pam_rule(stig_id, pamFile, pamMod, failNotice) }}

{%- else %}

#file {{ pamMod }} exists
#{{ pamMod }} showfailed already present
notify_V{{ stig_id }}-{{ pamMod }}:
  cmd.run:
    - name: 'printf "{{ pamMod }} already configured for ''showfailed'' in {{ pamFile }}\n"'

{%- endif %}
