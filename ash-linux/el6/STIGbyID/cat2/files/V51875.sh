#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51875
# Finding ID:	V-51875
# Version:	
# Finding Level:	Medium
#
#     Users need to be aware of activity that occurs regarding their 
#     account. Providing users with information regarding the number 
#     of unsuccessful attempts that were made to login to their 
#     account allows the user to determine if any unauthorized 
#     activity has occurred and gives them an opportunity to notify 
#     administrators. 
#
# CCI: CCI-000366
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-51875"
diag_out "  OS must display count of failed"
diag_out "  login attempts since last logon"
diag_out "----------------------------------"

