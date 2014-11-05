#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38456
# Finding ID:	V-38456
# Version:	RHEL-06-000002
# Finding Level:	Low
#
#     Ensuring that "/var" is mounted on its own partition enables the 
#     setting of more restrictive mount options. This helps protect system 
#     services such as daemons or other programs which use it. It is not 
#     uncommon for the "/var" directory to contain world-writable 
#     directories, installed by other software packages. 
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
diag_out "STIG Finding ID: V-38456"
diag_out "  The /var directory should be on"
diag_out "  its own device"
diag_out "----------------------------------"
