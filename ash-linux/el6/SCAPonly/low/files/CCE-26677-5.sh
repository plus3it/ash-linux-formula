#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26677-5.sls
#
# Rule ID: kernel_module_udf_disabled
#
# Rule Summary: Disable Mounting of udf
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
diag_out "  Disable udf support"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

