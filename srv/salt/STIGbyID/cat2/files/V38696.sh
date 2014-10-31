#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38696
# Finding ID:	V-38696
# Version:	RHEL-06-000303
# Finding Level:	Medium
#
#     The operating system must employ automated mechanisms, per 
#     organization defined frequency, to detect the addition of 
#     unauthorized components/devices into the operating system. By 
#     default, AIDE does not install itself for periodic execution. 
#     Periodically running AIDE may reveal unexpected changes in installed 
#     files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38696"
diag_out "  OS must be configured to detect"
diag_out "  additon of unauthorized"
diag_out "  components/devices"
diag_out "----------------------------------"

