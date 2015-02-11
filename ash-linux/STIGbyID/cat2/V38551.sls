# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38551
# Finding ID:	V-38551
# Version:	RHEL-06-000106
# Finding Level:	Medium
#
#     The operating system must connect to external networks or information 
#     systems only through managed IPv6 interfaces consisting of boundary 
#     protection devices arranged in accordance with an organizational 
#     security architecture. The "ip6tables" service provides the system's 
#     host-based firewalling capability for IPv6 and ICMPv6.
#
#  CCI: CCI-001098
#  NIST SP 800-53 :: SC-7 b
#  NIST SP 800-53A :: SC-7.1 (iv)
#  NIST SP 800-53 Revision 4 :: SC-7 c
#
############################################################

script_V38551-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38551.sh

service_V38551:
  service:
    - name: ip6tables
    - running
    - enable: True
