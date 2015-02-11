# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38613
# Finding ID:	V-38613
# Version:	RHEL-06-000237
# Finding Level:	Medium
#
#     The system must not permit root logins using remote access programs 
#     such as ssh. Permitting direct root login reduces auditable 
#     information about who ran privileged commands on the system and also 
#     allows direct attack attempts on root's password.
#
#  CCI: CCI-000770
#  NIST SP 800-53 :: IA-2 (5) (b)
#  NIST SP 800-53A :: IA-2 (5).2 (ii)
#  NIST SP 800-53 Revision 4 :: IA-2 (5)
#
############################################################

script_V38613-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38613.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^PermitRootLogin')
 %}
file_V38613-repl:
  file.replace:
  - name: '/etc/ssh/sshd_config'
  - pattern: '^PermitRootLogin.*$'
  - repl: 'PermitRootLogin no'
{% else %}
file_V38613-append:
  file.append:
  - name: '/etc/ssh/sshd_config'
  - text:
    - ' '
    - '# Disable host-based authentication (per STIG V-38613)'
    - 'PermitRootLogin no'
{% endif %}

