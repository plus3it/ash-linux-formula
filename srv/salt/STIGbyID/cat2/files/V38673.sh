#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38673
# Finding ID:	V-38673
# Version:	RHEL-06-000307
# Finding Level:	Medium
#
#     The operating system must ensure unauthorized, security-relevant 
#     configuration changes detected are tracked. By default, AIDE does not 
#     install itself for periodic execution. Periodically running AIDE may 
#     reveal unexpected changes in installed files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38673"
diag_out "  AIDE must be configured to run"
diag_out "  on a regular, periodic basis"
diag_out "----------------------------------"

