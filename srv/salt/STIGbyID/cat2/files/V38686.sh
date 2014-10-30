#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38686
# Finding ID:	V-38686
# Version:	RHEL-06-000320
# Finding Level:	Medium
#
#     The systems local firewall must implement a deny-all, 
#     allow-by-exception policy for forwarded packets. In "iptables" the 
#     default policy is applied only after all the applicable rules in the 
#     table are examined for a match. Setting the default policy to "DROP" 
#     implements proper design for a firewall, ...
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38686"
diag_out "  system-level firewall must"
diag_out "  default to a deny-all policy for"
diag_out "  forwarded packets."
diag_out "----------------------------------"

