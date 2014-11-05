#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38655
# Finding ID:	V-38655
# Version:	RHEL-06-000271
# Finding Level:	Low
#
#     The noexec option must be added to removable media partitions. 
#     Allowing users to execute binaries from removable media such as USB 
#     keys exposes the system to potential compromise.
#
#  CCI: CCI-000087
#  NIST SP 800-53 :: AC-19 e
#  NIST SP 800-53A :: AC-19.1 (v)
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38655"
diag_out "  The noexec option must be added"
diag_out "  to removable media partitions."
diag_out "----------------------------------"
