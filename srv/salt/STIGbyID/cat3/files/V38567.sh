#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38567
# Finding ID:	V-38567
# Version:	RHEL-06-000198
# Finding Level:	Low
#
#     The audit system must be configured to audit all use of setuid 
#     programs. Privileged programs are subject to escalation-of-privilege 
#     attacks, which attempt to subvert their normal role of providing some 
#     necessary but limited capability. As such, motivation exists to 
#     monitor these programs for unusual activity.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38567"
diag_out "  Audit system must log all use"
diag_out "  of setuid programs"
diag_out "----------------------------------"
