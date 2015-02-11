# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38614
# Finding ID:	V-38614
# Version:	RHEL-06-000239
# Finding Level:	High
#
#     The SSH daemon must not allow authentication using an empty password. 
#     Configuring this setting for the SSH daemon provides additional 
#     assurance that remote login via SSH will require a password, even in 
#     the event of misconfiguration elsewhere.
#
############################################################

script_V38614-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38614.sh

{% set sshConfigFile = '/etc/ssh/sshd_config' %}

{% if salt['file.search'](sshConfigFile, '^PermitEmptyPasswords .*') %}
  {% if salt['file.search'](sshConfigFile, '^PermitEmptyPasswords no') %}
file_V38614:
  cmd.run:
  - name: 'echo "Empty passwords already disabled in ''{{ sshConfigFile }}''"'
  {% else %}
file_V38614:
  file.replace:
  - name: '{{ sshConfigFile }}'
  - pattern: "^PermitEmptyPasswords .*"
  - repl: "PermitEmptyPasswords no"
  {% endif %}
{% else %}
file_V38614:
  file.append:
  - name: '{{ sshConfigFile }}'
  - text:
    - ' '
    - '# SSH Must not allow empty passwords (per STIG V-38614)'
    - 'PermitEmptyPasswords no'
{% endif %}
