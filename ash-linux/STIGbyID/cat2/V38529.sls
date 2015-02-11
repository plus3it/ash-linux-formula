# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38529
# Finding ID:	V-38529
# Version:	RHEL-06-000089
# Finding Level:	Medium
#
#     The system must not accept IPv4 source-routed packets by default. 
#     Accepting source-routed packets in the IPv4 protocol has few 
#     legitimate uses. It should be disabled unless it is absolutely 
#     required.
#
#  CCI: CI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38529-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38529.sh

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv4.conf.default.accept_source_route') %}
file_V38529-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^net.ipv4.conf.default.accept_source_route.*$'
    - repl: 'net.ipv4.conf.default.accept_source_route = 0'
{% else %}
file_V38529-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Disable ICMPv4 secure redirect packtes'
      - 'net.ipv4.conf.default.accept_source_route = 0'
{% endif %}
