#!/bin/sh
# Finding ID:	RHEL-07-021011
# Version:	RHEL-07-021011_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	Files systems that are used with removable media must be
#	mounted to prevent files with the setuid and setgid bit set
#	from being executed.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-021011"
diag_out "   Files systems that are used with"
diag_out "   removable media must be mounted to"
diag_out "   prevent files with the setuid and"
diag_out "   setgid bit set from being executed."
diag_out "----------------------------------------"
