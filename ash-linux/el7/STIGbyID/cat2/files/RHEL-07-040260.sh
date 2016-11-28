#!/bin/sh
# Finding ID:	RHEL-07-040260
# Version:	RHEL-07-040260_rule
# SRG ID:	SRG-OS-000423-GPOS-00187
# Finding Level:	medium
# 
# Rule Summary:
#	All networked systems must have SSH installed.
#
# CCI-002418 
# CCI-002421 
# CCI-002420 
# CCI-002422 
#    NIST SP 800-53 Revision 4 :: SC-8 
#    NIST SP 800-53 Revision 4 :: SC-8 (1) 
#    NIST SP 800-53 Revision 4 :: SC-8 (2) 
#    NIST SP 800-53 Revision 4 :: SC-8 (2) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040260"
diag_out "   All networked systems must have SSH"
diag_out "   installed."
diag_out "----------------------------------------"
