#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38513
# Finding ID:	V-38513
# Version:	RHEL-06-000120
# Finding Level:	Medium
#
#     The systems local IPv4 firewall must implement a deny-all, 
#     allow-by-exception policy for inbound packets. In "iptables" the 
#     default policy is applied only after all the applicable rules in the 
#     table are examined for a match. Setting the default policy to "DROP" 
#     implements proper design for a firewall, ...
#
#  CCI: CCI-000066
#  NIST SP 800-53 :: AC-17 e
#  NIST SP 800-53A :: AC-17.1 (v)
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38513"
diag_out "  The iptables service must enable"
diag_out "  a default 'deny-all' stance on"
diag_out "  inbound packets"
diag_out "----------------------------------"
