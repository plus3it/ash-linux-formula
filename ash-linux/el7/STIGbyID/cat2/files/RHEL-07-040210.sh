#!/bin/sh
# Finding ID:	RHEL-07-040210
# Version:	RHEL-07-040210_rule
# SRG ID:	SRG-OS-000355-GPOS-00143
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must, for networked systems, synchronize
#	clocks with a server that is synchronized to one of the
#	redundant United States Naval Observatory (USNO) time servers,
#	a time server designated for the appropriate DoD network
#	(NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
#
# CCI-001891 
# CCI-002046 
#    NIST SP 800-53 Revision 4 :: AU-8 (1) (a) 
#    NIST SP 800-53 Revision 4 :: AU-8 (1) (b) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-040210"
diag_out "   The operating system must, for"
diag_out "   networked systems, synchronize"
diag_out "   clocks with a server that is"
diag_out "   synchronized to one of the redundant"
diag_out "   United States Naval Observatory"
diag_out "   (USNO) time servers, a time server"
diag_out "   designated for the appropriate DoD"
diag_out "   network (NIPRNet/SIPRNet), and/or"
diag_out "   the Global Positioning System (GPS)."
diag_out "----------------------------------------"
