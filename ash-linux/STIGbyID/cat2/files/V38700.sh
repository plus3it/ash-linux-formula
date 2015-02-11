#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38700
# Finding ID:	V-38700
# Version:	RHEL-06-000305
# Finding Level:	Medium
#
#     The operating system must provide a near real-time alert when any of 
#     the organization defined list of compromise or potential compromise 
#     indicators occurs. By default, AIDE does not install itself for 
#     periodic execution. Periodically running AIDE may reveal unexpected 
#     changes in installed files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38700"
diag_out "  system must provide as near to"
diag_out "  real-time alerting when"
diag_out "  compromise inidators are found"
diag_out "----------------------------------"

