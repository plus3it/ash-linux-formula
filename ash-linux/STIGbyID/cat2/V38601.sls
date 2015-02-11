# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38601
# Finding ID:	V-38601
# Version:	RHEL-06-000081
# Finding Level:	Medium
#
#     The system must not send ICMPv4 redirects from any interface. Sending 
#     ICMP redirects permits the system to instruct other systems to update 
#     their routing information. The ability to send ICMP redirects is only 
#     appropriate for routers.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53 :: CM-6.1 (iv)
#  NIST SP 800-53 :: CM-6 b
#
############################################################


script_V38601-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38601.sh

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv4.conf.all.send_redirects')
 %}
file_V38601-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^net.ipv4.conf.all.send_redirects.*$'
    - repl: 'net.ipv4.conf.all.send_redirects = 0'
{% else %}
file_V38601-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Disable sedning ICMP redirects (per STIG V-38601)'
      - 'net.ipv4.conf.all.send_redirects = 0'
{% endif %}

