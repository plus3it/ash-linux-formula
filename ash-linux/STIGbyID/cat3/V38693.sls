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

{%- set stig_id = '38693' %}
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set parmName = 'maxrepeat' %}

#define macro to set maxrepeat to '3'
{%- macro maxrepeat_template(stig_id, file, param_name) %}
maxrepeat_V{{ stig_id }}-setThree:
  file.replace:
    - name : {{ file }}
    - pattern: '{{ param_name }}=[-]?[\S]*'
    - repl: '{{ param_name }}=3'
    - onlyif: 
      - 'grep -E -e "pam_cracklib.so.*{{ param_name }}=[-]?[\S]*" {{ file }}'
maxrepeat_add_V{{ stig_id }}-setThree:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<tok_pass>password[ \t]*.*pam_cracklib.so.*)'
    - repl: '\g<tok_pass> {{ param_name }}=3'
    - onlyif: 
      - 'grep -v -E -e "pam_cracklib.so.*{{ param_name }}.*" {{ file }}'
notify_V{{ stig_id }}-maxrepeat_setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters set to ''3'' (per STIG ID V-{{ stig_id }})"'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh

{%- if salt['file.file_exists'](checkFile) %}
#system-auth-ac exists
  {%- if not salt['cmd.run']('grep -c -E -e "[ \t]' + parmName + '=3[ \t]*" ' + checkFile ) == '0' %}
#maxrepeat already set to 3
notify_V{{ stig_id }}-maxrepeat_setThree:
  cmd.run:
    - name: 'echo "Passwords'' repeating characters already capped at ''3'' (per STIG ID V-{{ stig_id }})"'
  {%- else %}
#maxrepeat not yet set to 3; 
#use the macro to add the parameter, or update it if the parameter is set to a bad value
{{ maxrepeat_template(stig_id, checkFile, parmName) }}

  {%- endif %}
{%- else %}
#system-auth-ac did not exist when jinja templated the file; system-auth-ac 
#will be configured by authconfig.sls in the include statement. 
#Use the macro to set maxrepeat to 3.
{{ maxrepeat_template(stig_id, checkFile, parmName) }}

{%- endif %}
