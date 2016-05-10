#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38566
# Finding ID:	V-38566
# Version:	RHEL-06-000197
# Finding Level:	Low
#
#     The audit system must be configured to audit failed attempts to 
#     access files and programs. Unsuccessful attempts to access files 
#     could be an indicator of malicious activity on a system. Auditing 
#     these events could serve as evidence of potential system compromise.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38566"
diag_out "  Audit system must log failed"
diag_out "  attempts to access files and"
diag_out "  programs"
diag_out "----------------------------------"
