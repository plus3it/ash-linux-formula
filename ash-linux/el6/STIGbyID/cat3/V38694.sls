# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38694
# Finding ID:	V-38694
# Version:	RHEL-06-000335
# Finding Level:	Low
#
#     The operating system must manage information system identifiers for 
#     users and devices by disabling the user identifier after an 
#     organization defined time period of inactivity. Disabling inactive 
#     accounts ensures that accounts which may not have been responsibly 
#     removed are not available to attackers who may have compromised their 
#     credentials.
#
#  CCI: CCI-000795
#  NIST SP 800-53 :: IA-4 e
#  NIST SP 800-53A :: IA-4.1 (iii)
#  NIST SP 800-53 Revision 4 :: IA-4 e
#
############################################################

{%- set stigId = 'V38694' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- set checkFile = '/etc/default/useradd' %}
{%- set parmName = 'INACTIVE' %}

# If live 'INACTIVE' parameter is already set...
{%- if salt.file.search(checkFile, '^' + parmName + '=') %}
  # ...Check if correct value
  {%- if salt.file.search(checkFile, '^' + parmName + '=35') %}
set_{{ stigId }}-inactive:
  cmd.run:
    - name: 'echo "Account inactivity-lockout already set to 35 days"'
  # ...If not, set correct value
  {%- else %}
set_{{ stigId }}-inactive:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^{{ parmName }}=.*$'
    - repl: '{{ parmName }}=35'
  {%- endif %}
# If no live 'INACTIVE' parameter is set...
{%- else %}
  # ...See if an appropriate commented value exists
  {%- if salt.file.search(checkFile, '#[ 	]*' + parmName + '=35') %}
set_{{ stigId }}-inactive:
  file.uncomment:
    - name: {{ checkFile }}
    - regex: '{{ parmName }}=35'
  # ...and append if necessary
  {%- else %}
set_{{ stigId }}-inactive:
  file.append:
    - name: {{ checkFile }}
    - text: '{{ parmName }}=35'
  {%- endif %}
{%- endif %}
