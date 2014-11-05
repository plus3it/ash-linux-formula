#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38672
# Finding ID:	V-38672
# Version:	RHEL-06-000289
# Finding Level:	Low
#
#     The netconsole service must be disabled unless required. The 
#     "netconsole" service is not necessary unless there is a need to debug 
#     kernel panics, which is not common.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38672"
diag_out "  The netconsole service should"
diag_out "  be disabled"
diag_out "----------------------------------"
