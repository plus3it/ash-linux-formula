# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38533
# Finding ID:	V-38533
# Version:	RHEL-06-000091
# Finding Level:	Low
#
#     The system must ignore ICMPv4 redirect messages by default. This 
#     feature of the IPv4 protocol has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38533-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38533.sh

{% if salt['sysctl.get']('net.ipv4.conf.default.accept_redirects') == '0' %}
sysctl_V38533-noRedirects:
  cmd.run:
    - name: 'echo "System already configured to ignore ICMPv4 redirect messages"'
{% else %}
sysctl_V38533-noRedirects:
  sysctl.present:
    - name: 'net.ipv4.conf.default.accept_redirects'
    - value: '0'
{% endif %}
