#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38541
# Finding ID:	V-38541
# Version:	RHEL-06-000183
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the 
#     systems Mandatory Access Control (MAC) configuration (SELinux). The 
#     system's mandatory access policy (SELinux) should not be arbitrarily 
#     changed by anything other than administrator action. All changes to 
#     MAC policy should be audited.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38541"
diag_out "  Audit system must be configured"
diag_out "  to audit modifications to the"
diag_out "  SELinx MAC profiles"
diag_out "-----------------------------------"
