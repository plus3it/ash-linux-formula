#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26499-4
#
# Rule Summary: Set 'nodev' option on '/tmp' partition
#
# Rule Text: The nodev mount option can be used to prevent device files 
#            from being created in /tmp. Legitimate character and block 
#            devices should not exist within temporary directories like 
#            /tmp. Add the nodev option to the fourth column of 
#            /etc/fstab for the line which controls mounting of /tmp.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'nodev' to the '/tmp'"
diag_out "  filesystem's mount options."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

