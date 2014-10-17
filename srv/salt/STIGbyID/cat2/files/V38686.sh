#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38686
# Finding ID:	V-38686
# Version:	
# Finding Level:	Medium
#
#     The systems local firewall must implement a deny-all, 
#     allow-by-exception policy for forwarded packets. In "iptables" the 
#     default policy is applied only after all the applicable rules in the 
#     table are examined for a match. Setting the default policy to "DROP" 
#     implements proper design for a firewall, ...
#
############################################################

