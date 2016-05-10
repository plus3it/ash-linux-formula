#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38666
# Finding ID:	V-38666
# Version:	RHEL-06-000284
# Finding Level:	High
#
#     The system must use and update a DoD-approved virus scan program. 
#     Virus scanning software can be used to detect if a system has been 
#     compromised by computer viruses, as well as to limit their spread to 
#     other systems.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38666"
diag_out "  System must run a DoD-approved"
diag_out "  anti-virus scanner with updated"
diag_out "  virus definitions (< 7do)"
diag_out "----------------------------------"

