#!/bin/sh
#
# Finding ID:
# Version:		sysctl_kernel_ipv6_disable
# SRG ID:
# Finding Level:	medium
#
# Rule Summary:
#	Any unnecessary network stacks - including IPv6 - should
#	be disabled, to reduce the vulnerability to exploitation.
#	Disable IPv6 on all network interfaces in a manner that
#	allows other services and system functionality requiring
#	the IPv6 stack loaded to work.
#
# CCI-1551
#    NIST SP 800-53 Revision 4 :: CM-7
#    CIS RHEL 7 Benchmark 1.1.0 :: 4.4.2
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-------------------------------------------"
diag_out "STIG Finding ID: sysctl_kernel_ipv6_disable"
diag_out "   The IPv6 network-stack should be"
diag_out "   disabled, to reduce the"
diag_out "   vulnerability to exploitation."
diag_out "-------------------------------------------"
