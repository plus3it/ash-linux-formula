# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38610
# Finding ID:	V-38610
# Version:	RHEL-06-000231
# Finding Level:	Low
#
#     The SSH daemon must set a timeout count on idle sessions. This 
#     ensures a user login will be terminated as soon as the 
#     "ClientAliveCountMax" is reached.
#
#  CCI: CCI-000879
#  NIST SP 800-53 :: MA-4 e
#  NIST SP 800-53A :: MA-4.1 (vi)
#  NIST SP 800-53 Revision 4 :: MA-4 e
#
############################################################

script_V38610-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38610.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^ClientAliveCountMax') %}
  {% if salt['file.search']('/etc/ssh/sshd_config', '^ClientAliveCountMax 0') %}
file_V38610-configSet:
  cmd.run:
    - name: 'echo "ClientAliveCountMax already meets STIG-defined requirements"'
  {% else %}
file_V38610-configSet:
  file.replace:
    - name: '/etc/ssh/sshd_config'
    - pattern: '^ClientAliveCountMax.*$'
    - repl: 'ClientAliveCountMax 0'
  {% endif %}
{% else %}
file_V38610-configSet:
  file.append:
    - name: '/etc/ssh/sshd_config'
    - text:
      - ' '
      - '# SSH service must set a session idle-timeout (per STIG V-38610)'
      - 'ClientAliveCountMax 0'
{% endif %}
