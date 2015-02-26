#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26544-7
#
# Rule ID: kernel_module_freevxfs_disabled
#
# Rule Summary: Disable Mounting of freevxfs
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
diag_out "  Disable freevxfs support"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

