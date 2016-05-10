#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38527
# Finding ID:	V-38527
# Version:	RHEL-06-000171
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through clock_settime. Arbitrary changes to the system 
#     time can be used to obfuscate nefarious activities in log files, as 
#     well as to confuse network services that are highly dependent upon an 
#     accurate system time (such as shd). All changes to the system time
#     should be audited.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "-----------------------------------"
diag_out "STIG Finding ID: V-38527"
diag_out "  audit system must be configured"
diag_out "  to audit all attempts to alter"
diag_out "  system time through clock_settime"
diag_out "-----------------------------------"
