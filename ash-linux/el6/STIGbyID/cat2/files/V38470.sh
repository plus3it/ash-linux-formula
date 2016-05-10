#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38470
# Finding ID:	V-38470
# Version:	RHEL-06-000005
# Finding Level:	Medium
#
#     The audit system must alert designated staff members when the audit 
#     storage volume approaches capacity. Notifying administrators of an 
#     impending disk space problem may allow them to take corrective action 
#     prior to any disruption.
#
#  CCI: CCI-000138
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (ii)
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38470"
diag_out "  Configure e-mail warning when"
diag_out "  audit-partition begins to become"
diag_out "  too full"
diag_out "----------------------------------"

