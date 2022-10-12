#!/bin/sh
#
# Finding ID:	
# Version: mount_option_tmp_noexec
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The noexec mount option can be used to prevent binaries
#       from being executed out of /tmp.
#
# CCE-82139-7
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
