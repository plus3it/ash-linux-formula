#!/bin/sh
# STIG ID:	RHEL-07-020020
# Rule ID:	SV-86595r2_rule
# Vuln ID:	V-71971
# SRG ID:	SRG-OS-000324-GPOS-00125
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must prevent non-privileged users from
#	executing privileged functions to include disabling,
#	circumventing, or altering implemented security
#	safeguards/countermeasures.
#
# CCI-002165 
# CCI-002235 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#    NIST SP 800-53 Revision 4 :: AC-6 (10) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-020020"
diag_out "   The operating system must prevent"
diag_out "   non-privileged users from executing"
diag_out "   privileged functions."
diag_out "----------------------------------------"
