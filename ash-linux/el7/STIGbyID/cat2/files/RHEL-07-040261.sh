#!/bin/sh
# Finding ID:	RHEL-07-040261
# Version:	RHEL-07-040261_rule
# SRG ID:	SRG-OS-000423-GPOS-00187
# Finding Level:	medium
# 
# Rule Summary:
#	All networked systems must use SSH for confidentiality and
#	integrity of transmitted and received information as well as
#	information during preparation for transmission.
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
diag_out "STIG Finding ID: RHEL-07-040261"
diag_out "   All networked systems must use SSH"
diag_out "   for confidentiality and integrity of"
diag_out "   transmitted and received information"
diag_out "   as well as information during"
diag_out "   preparation for transmission."
diag_out "----------------------------------------"
