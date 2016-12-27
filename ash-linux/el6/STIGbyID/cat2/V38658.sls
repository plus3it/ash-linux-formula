# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38658
# Finding ID:	V-38658
# Version:	RHEL-06-000274
# Finding Level:	Medium
#
#     The system must prohibit the reuse of passwords within twenty-four 
#     iterations. Preventing reuse of previous passwords helps ensure that 
#     a compromised password is not reused by a user.
#
#  CCI: CCI-000200
#  NIST SP 800-53 :: IA-5 (1) (e)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1)
#
############################################################

include:
  - ash-linux.authconfig

{%- set stig_id = '38658' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set pam_cfg_file = '/etc/pam.d/system-auth-ac' %}
{%- set pam_parameter = 'remember' %}
{%- set pam_param_value = '24' %}

#define macro to configure the pam module in a file
{%- macro pam_remember_password(stig_id, file, param, value) %}
replace_V{{ stig_id }}-{{ param }}:
  file.replace:
    - name: '{{ file }}'
    - pattern: ' {{ param }}=[\S]*'
    - repl: ' {{ param }}={{ value }}'
    - onlyif:
      - 'grep -E -e "password[ \t]*sufficient[ \t]*pam_unix.so.*{{ param }}=[\S]*" {{ file }}'
      - 'test $(grep -c -E -e "password[ \t]*sufficient[ \t]*pam_unix.so.*{{ param }}={{ value }}" {{ file }}) -eq 0'

add_V{{ stig_id }}-{{ param }}:
  file.replace:
    - name: '{{ file }}'
    - pattern: '^(?P<srctok>password[ \t]*sufficient[ \t]*pam_unix.so.*$)'
    - repl: '\g<srctok> {{ param }}={{ value }}'
    - onlyif:
      - 'test $(grep -c -E -e "password[ \t]*sufficient[ \t]*pam_unix.so.*{{ param }}=" {{ file }}) -eq 0'

notify_V{{ stig_id }}-reuseParm:
  cmd.run:
    - name: 'echo "Password re-use parameter (remember) set to {{ value }} (per STIG ID V-{{ stig_id }})."'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

{%- if not salt.file.file_exists(pam_cfg_file) %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement. 
#use macro to set the parameter
{{ pam_remember_password(stig_id, pam_cfg_file, pam_parameter, pam_param_value) }}


{%- elif not salt.file.search(pam_cfg_file, 'password[ \t]*sufficient[ \t]*pam_unix.so.*' ~ pam_parameter ~ '=' ~ pam_param_value ~ '[\s]*') %}

#file {{ pam_cfg_file }} exists
#'remember' parameter not yet configured
#use macro to set the parameter
{{ pam_remember_password(stig_id, pam_cfg_file, pam_parameter, pam_param_value) }}

{%- else %}

#file {{ pam_cfg_file }} exists
#'remember' parameter already configured
notify_V{{ stig_id }}-reuseParm:
  cmd.run:
    - name: 'echo "Password re-use parameter ({{ pam_parameter }}) already set to {{ pam_param_value }} (per STIG ID V-{{ stig_id }})."'

{%- endif %}
