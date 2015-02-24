# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38532
# Finding ID:	V-38532
# Version:	RHEL-06-000090
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 secure redirect packets by default. 
#     Accepting "secure" ICMP redirects (from those gateways listed as 
#     default gateways) has few legitimate uses. It should be disabled 
#     unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38532-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38532.sh
    - cwd: '/root'

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv4.conf.default.secure_redirects') %}
file_V38532-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^net.ipv4.conf.default.secure_redirects.*$'
    - repl: 'net.ipv4.conf.default.secure_redirects = 0'
{% else %}
file_V38532-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Disable ICMPv4 secure redirect packtes'
      - 'net.ipv4.conf.default.secure_redirects = 0'
{% endif %}
