#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38545
# Finding ID:	V-38545
# Version:	RHEL-06-000185
# Finding Level:	Low
#
#     The audit system must be configured to audit all discretionary access 
#     control permission modifications using chown. The changing of file 
#     permissions could indicate that a user is attempting to gain access 
#     to information that would otherwise be disallowed. Auditing DAC 
#     modifications can facilitate the identification of patterns of abuse 
#     among both authorized and unauthorized users.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "------------------------------------"
diag_out "STIG Finding ID: V-38545"
diag_out "  Audit system log all chown-"
diag_out "  based DAC permission modifications"
diag_out "------------------------------------"
