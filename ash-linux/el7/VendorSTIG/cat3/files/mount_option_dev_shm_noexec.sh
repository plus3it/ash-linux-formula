#!/bin/sh
#
# Finding ID:	
# Version:	mount_option_dev_shm_noexec
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#	Allowing users to execute binaries from world-writable
#	directories such as /dev/shm can expose the system to
#	potential compromise.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.16
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------------"
diag_out "STIG Finding ID: mount_option_dev_shm_noexec"
diag_out "   Set noexec option on /dev/shm to prevent"
diag_out "   abusive binary-execs from /dev/shm."
diag_out "--------------------------------------------"
