#!/bin/bash
# Finding ID:	
# Version:	mount_option_tmp_noexec
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The noexec mount option can be used to prevent binaries
#       from being executed out of /tmp. Add the noexec option
#       to the fourth column of /etc/fstab for the line which
#       controls mounting of /tmp.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.4
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: mount_option_tmp_noexec"
diag_out "   Allowing users to execute binaries"
diag_out "   from world-writable directories such"
diag_out "   as /tmp should never be necessary in"
diag_out "   normal operation and can expose the"
diag_out "   system to potential compromise."
diag_out "----------------------------------------"
