# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38616
# Finding ID:	V-38616
# Version:	RHEL-06-000241
# Finding Level:	Low
#
#     The SSH daemon must not permit user environment settings. SSH 
#     environment options potentially allow users to bypass access 
#     restriction in some configurations.
#
############################################################

script_V38616-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38616.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^PermitUserEnvironment') %}
  {% if salt['file.search']('/etc/ssh/sshd_config', '^PermitUserEnvironment no')
file_V38616-configSet:
  cmd.run:
  - name: 'echo "PermitUserEnvironment already meets STIG-defined requirements"'
  {% else %}
file_V38616-configSet:
  file.replace:
  - name: '/etc/ssh/sshd_config'
  - pattern: '^PermitUserEnvironment.*$'
  - repl: 'PermitUserEnvironment no'
  {% endif %}
{% else %}
file_V38616-configSet:
  file.append:
  - name: '/etc/ssh/sshd_config'
  - text:
    - ' '
    - '# SSH service must not allow setting of user environment options (per STIG V-38616)'
    - 'PermitUserEnvironment no'
{% endif %}

