#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38455
# Finding ID:	V-38455
# Version:	RHEL-06-000001
# Finding Level:	Low
#
#     The "/tmp" partition is used as temporary storage by many programs. 
#     Placing "/tmp" in its own partition enables the setting of more 
#     restrictive mount options, which can help protect programs which use 
#     it. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38455"
diag_out "  The /tmp directory should be on"
diag_out "  its own device"
diag_out "----------------------------------"
