# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38523
# Finding ID:	V-38523
# Version:	RHEL-06-000083
# Finding Level:	Medium
#
#     The system must not accept IPv4 source-routed packets on any 
#     interface. Accepting source-routed packets in the IPv4 protocol has 
#     few legitimate uses. It should be disabled unless it is absolutely 
#     required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38523-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38523.sh
    - cwd: '/root'

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv4.conf.all.accept_source_route') %}
file_V38523-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^net.ipv4.conf.all.accept_source_route.*$'
    - repl: 'net.ipv4.conf.all.accept_source_route = 0'
{% else %}
file_V38523-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ''
      - '# Disable source-routed packets'
      - 'net.ipv4.conf.all.accept_source_route = 0'
{% endif %}
