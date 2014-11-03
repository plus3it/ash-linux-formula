#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38484
# Finding ID:	V-38484
# Version:	RHEL-06-000507
# Finding Level:	Medium
#
#     The operating system, upon successful logon, must display to the user 
#     the date and time of the last logon or access via ssh. Users need to 
#     be aware of activity that occurs regarding their account. Providing 
#     users with information regarding the date and time of their last 
#     successful login allows the user to determine if any unauthorized
#     activity has occurred and gives them an opportunity to notify
#     administrators.
#
#  CCI: CCI-000052
#  NIST SP 800-53 :: AC-9
#  NIST SP 800-53A :: AC-9.1
#  NIST SP 800-53 Revision 4 :: AC-9
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38484"
diag_out "  System must display last logon"
diag_out "  or access via ssh"
diag_out "----------------------------------"
