#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38670
# Finding ID:	V-38670
# Version:	RHEL-06-000306
# Finding Level:	Medium
#
#     The operating system must detect unauthorized changes to software and 
#     information. By default, AIDE does not install itself for periodic 
#     execution. Periodically running AIDE may reveal unexpected changes in 
#     installed files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38670"
diag_out "  AIDE must be configured to run"
diag_out "  on a regular, periodic basis"
diag_out "----------------------------------"

