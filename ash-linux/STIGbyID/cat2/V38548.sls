# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38548
# Finding ID:	V-38548
# Version:	RHEL-06-000099
# Finding Level:	Medium
#
#     The system must ignore ICMPv6 redirects by default. An illicit ICMP 
#     redirect message could result in a man-in-the-middle attack.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38548-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38548.sh

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv6.conf.default.accept_redirects') %}
file_V38548-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^net.ipv6.conf.default.accept_redirects.*$'
    - repl: 'net.ipv6.conf.default.accept_redirects = 0'
{% else %}
file_V38548-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Disable ICMPv6 redirects (per STIG V-38548)'
      - 'net.ipv6.conf.default.accept_redirects = 0'
{% endif %}
