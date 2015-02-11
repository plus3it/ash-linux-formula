#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38473
# Finding ID:	V-38473
# Version:	RHEL-06-000007
# Finding Level:	Low
#
#     Ensuring that "/home" is mounted on its own partition enables the 
#     setting of more restrictive mount options, and also helps ensure that 
#     users cannot trivially fill partitions used for log or audit data 
#     storage. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38473"
diag_out "  The /home directory should be on"
diag_out "  its own device"
diag_out "----------------------------------"
