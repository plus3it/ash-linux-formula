# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38612
# Finding ID:	V-38612
# Version:	RHEL-06-000236
# Finding Level:	Medium
#
#     The SSH daemon must not allow host-based authentication. SSH trust 
#     relationships mean a compromise on one host can allow an attacker to 
#     move trivially to other hosts.
#
#  CCI: CCI-000766
#  NIST SP 800-53 :: IA-2 (2)
#  NIST SP 800-53A :: IA-2 (2).1
#  NIST SP 800-53 Revision 4 :: IA-2 (2)
#
############################################################

script_V38612-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38612.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^HostbasedAuthentication')
 %}
file_V38612-repl:
  file.replace:
    - name: '/etc/ssh/sshd_config'
    - pattern: '^HostbasedAuthentication.*$'
    - repl: 'HostbasedAuthentication no'
{% else %}
file_V38612-append:
  file.append:
    - name: '/etc/ssh/sshd_config'
    - text:
      - ' '
      - '# Disable host-based authentication (per STIG V-38612)'
      - 'HostbasedAuthentication no'
{% endif %}

