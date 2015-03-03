# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38692
# Finding ID:	V-38692
# Version:	RHEL-06-000334
# Finding Level:	Low
#
#     Accounts must be locked upon 35 days of inactivity. Disabling 
#     inactive accounts ensures that accounts which may not have been 
#     responsibly removed are not available to attackers who may have 
#     compromised their credentials.
#
#  CCI: CCI-000017
#  NIST SP 800-53 :: AC-2 (3)
#  NIST SP 800-53A :: AC-2 (3).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (3)
#
############################################################

script_V38692-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38692.sh
    - cwd: /root

{% set checkFile = '/etc/default/useradd' %}
{% set parmName = 'INACTIVE' %}

# If live 'INACTIVE' parameter is already set...
{% if salt['file.search'](checkFile, '^' + parmName + '=') %}
  # ...Check if correct value
  {% if salt['file.search'](checkFile, '^' + parmName + '=35') %}
set_V38692-inactive:
  cmd.run:
    - name: 'echo "Account inactivity-lockout already set to 35 days"'
  # ...If not, set correct value
  {% else %}
set_V38692-inactive:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^{{ parmName }}=.*$'
    - repl: '{{ parmName }}=35'
  {% endif %}
# If no live 'INACTIVE' parameter is set...
{% else %}
  # ...See if an appropriate commented value exists
  {% if salt['file.search'](checkFile, '#[ 	]*' + parmName + '=35') %}
set_V38692-inactive:
  file.uncomment:
    - name: {{ checkFile }}
    - regex: '{{ parmName }}=35'
  # ...and append if necessary
  {% else %}
set_V38692-inactive:
  file.append:
    - name: {{ checkFile }}
    - text: '{{ parmName }}=35'
  {% endif %}
{% endif %}
