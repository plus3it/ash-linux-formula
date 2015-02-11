#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26778-1
#
# Rule Summary: Set 'nodev' option on '/dev/shm' partition
#
# Rule Text: The nodev mount option can be used to prevent creation of 
#            device files in /dev/shm. Legitimate character and block 
#            devices should not exist within temporary directories like 
#            /dev/shm. Add the nodev option to the fourth column of 
#            /etc/fstab for the line which controls mounting of /dev/shm.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'nodev' to the '/dev/shm'"
diag_out "  filesystem's mount options."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

