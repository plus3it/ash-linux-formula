# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38607
# Finding ID:	V-38607
# Version:	RHEL-06-000227
# Finding Level:	High
#
#     The SSH daemon must be configured to use only the SSHv2 protocol. SSH 
#     protocol version 1 suffers from design flaws that result in security 
#     vulnerabilities and should not be used.
#
############################################################

script_V38607-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38607.sh

{% set sshConfigFile = '/etc/ssh/sshd_config' %}

{% if salt['file.search'](sshConfigFile, '^Protocol .*') %}
  {% if salt['file.search'](sshConfigFile, '^Protocol 2') %}
file_V38607:
  cmd.run:
  - name: 'echo "Protocol version 2 already forced in ''{{ sshConfigFile }}''"'
  {% else %}
file_V38607:
  file.replace:
  - name: '{{ sshConfigFile }}'
  - pattern: "^Protocol .*"
  - repl: "Protocol 2"
  {% endif %}
{% else %}
file_V38607:
  file.append:
  - name: '{{ sshConfigFile }}'
  - text:
    - ' '
    - '# SSH Must only allow Protocol Version 2 (per STIG V-38607)'
    - 'Protocol 2'
{% endif %}
