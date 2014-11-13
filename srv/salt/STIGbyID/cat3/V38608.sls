# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38608
# Finding ID:	V-38608
# Version:	RHEL-06-000230
# Finding Level:	Low
#
#     The SSH daemon must set a timeout interval on idle sessions. Causing 
#     idle users to be automatically logged out guards against compromises 
#     one system leading trivially to compromises on another.
#
#  CCI: CCI-001133
#  NIST SP 800-53 :: SC-10
#  NIST SP 800-53A :: SC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: SC-10
#
############################################################

script_V38608-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38608.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^Ciphers')
 %}
file_V38608-repl:
  file.replace:
  - name: '/etc/ssh/sshd_config'
  - pattern: '^ClientAliveInterval.*$'
  - repl: 'ClientAliveInterval 900'
{% else %}
file_V38608-append:
  file.append:
  - name: '/etc/ssh/sshd_config'
  - text:
    - ' '
    - '# SSH service must set a session idle-timeout (per STIG V-38608)'
    - 'ClientAliveInterval 900'
{% endif %}

