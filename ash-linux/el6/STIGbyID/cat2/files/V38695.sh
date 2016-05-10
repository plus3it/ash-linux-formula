#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38695
# Finding ID:	V-38695
# Version:	RHEL-06-000302
# Finding Level:	Medium
#
#     A file integrity tool must be used at least weekly to check for 
#     unauthorized file changes, particularly the addition of unauthorized 
#     system libraries or binaries, or for unauthorized modification to 
#     authorized system libraries or binaries. By default, AIDE does not 
#     install itself for periodic execution. Periodically running AIDE may 
#     reveal unexpected changes in installed files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38695"
diag_out "  A file-integrity tool must be"
diag_out "  installed and configured to run"
diag_out "  on at least a weekly basis"
diag_out "----------------------------------"

