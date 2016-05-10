#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-040300
# Version:	RHEL-07-040300_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must display the date and time of the last successful 
#     account logon upon a SSH (or other remote access method) logon.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: RHEL-07-040300"
diag_out "   OS must display count of failed"
diag_out "   login attempts since last logon"
diag_out "----------------------------------"
