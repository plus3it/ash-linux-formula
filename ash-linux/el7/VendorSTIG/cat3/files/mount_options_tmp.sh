#!/bin/sh
#
# Finding ID:	
# Version:	mount_option_tmp_nodev
# 		mount_option_tmp_noexec
# 		mount_option_tmp_nosuid
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The nodev mount option can be used to prevent device
#       files from being created in /tmp.
#
#       The noexec mount option can be used to prevent binaries
#       from being executed out of /tmp.
#
#       The nosuid mount option can be used to prevent
#       execution of setuid programs in /tmp.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.4
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.3
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: mount_options_tmp"
diag_out "   Set nodev, noexec and nosuid mount-"
diag_out "   options on /tmp to prevent abuses."
diag_out "--------------------------------------"
