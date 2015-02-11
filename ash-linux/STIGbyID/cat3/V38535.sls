# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38535
# Finding ID:	V-38535
# Version:	RHEL-06-000092
# Finding Level:	Low
#
#     The system must not respond to ICMPv4 sent to a broadcast address. 
#     Ignoring ICMP echo requests (pings) sent to broadcast or multicast 
#     addresses makes the system slightly more difficult to enumerate on 
#     the network.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38535-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38535.sh

{% if salt['sysctl.get']('net.ipv4.icmp_echo_ignore_broadcasts') == '1' %}
sysctl_V38535-noRedirects:
  cmd.run:
    - name: 'echo "System already ignores ICMPv4 packets sent to a broadcast address"'
{% else %}
sysctl_V38535-noRedirects:
  sysctl.present:
    - name: 'net.ipv4.icmp_echo_ignore_broadcasts'
    - value: '1'
{% endif %}
