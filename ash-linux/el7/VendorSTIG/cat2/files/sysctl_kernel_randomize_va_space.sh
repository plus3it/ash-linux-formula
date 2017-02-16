# Finding ID:
# Version:		sysctl_kernel_randomize_va_space
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
#    NIST SP 800-53 Revision 4 :: SC-30(2)
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.6.1
#
# Special note:
#	This state is designed only to patch what has been done
#	by a prior running of the `oscap` utility with the
#	 `--remediate` mode enabled
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "-------------------------------------------"
diag_out "STIG Finding ID: kernel_randomize_va_space"
diag_out "   Fix ASLR tunable name."
diag_out "-------------------------------------------"
