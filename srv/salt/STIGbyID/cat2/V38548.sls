# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38548
# Finding ID:	V-38548
# Version:	RHEL-06-000099
# Finding Level:	Medium
#
#     The system must ignore ICMPv6 redirects by default. An illicit ICMP 
#     redirect message could result in a man-in-the-middle attack.
#
############################################################

script_V38548-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38548.sh

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
    - '# Enable TCP SYN-cookies'
    - 'net.ipv6.conf.default.accept_redirects = 0'
{% endif %}
