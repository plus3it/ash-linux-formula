# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38444
# Finding ID:	V-38444
# Version:	RHEL-06-000523
# Finding Level:	Medium
#
#     The systems local IPv6 firewall must implement a deny-all, 
#     allow-by-exception policy for inbound packets. In "ip6tables" the 
#     default policy is applied only after all the applicable rules in the 
#     table are examined for a match. Setting the default policy to "DROP" 
#     implements proper design for a firewall, ...
#
############################################################

script_V38444-describe:
   cmd.script:
   - source: salt://STIGbyID/cat2/files/V38444.sh

cmd_V38444:
  iptables.set_policy:
  - table: filter
  - chain: INPUT
  - policy: DROP
  - family: ipv6
