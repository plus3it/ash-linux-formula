#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26800-3
#
# Rule ID: kernel_module_hfs_disabled
#
# Rule Summary: Disable Mounting of hfs
#
# Rule Text: Linux kernel modules which implement filesystems that are 
#            not needed by the local system should be disabled.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable hfs support"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

