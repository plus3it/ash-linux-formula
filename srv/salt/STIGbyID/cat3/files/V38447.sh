#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38447
# Finding ID:	V-38447
# Version:	RHEL-06-000519
# Finding Level:	Low
#
#     The system package management tool must verify contents of all files 
#     associated with packages. The hash on important files like system 
#     executables should match the information given by the RPM database. 
#     Executables with erroneous hashes could be a sign of nefarious 
#     activity on the system.
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
diag_out "STIG Finding ID: V-38447"
diag_out "  All files assosciated with the"
diag_out "  package management system should"
diag_out "  be verified"
diag_out "----------------------------------"
