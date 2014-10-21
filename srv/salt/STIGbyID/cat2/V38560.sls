# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38560
# Finding ID:	V-38560
# Version:	RHEL-06-000116
# Finding Level:	Medium
#
#     The operating system must connect to external networks or information 
#     systems only through managed IPv4 interfaces consisting of boundary 
#     protection devices arranged in accordance with an organizational 
#     security architecture. The "iptables" service provides the system's 
#     host-based firewalling capability for IPv4 and ICMP.
#
############################################################

script_V38560-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38560.sh

service_V38560:
  service:
  - name: iptables
  - running
  - enable: True
