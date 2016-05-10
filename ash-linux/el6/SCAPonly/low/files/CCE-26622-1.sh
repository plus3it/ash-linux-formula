#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26622-1
#
# Rule Summary: Set 'noexec' option on '/dev/shm' partition
#
# Rule Text: The noexec mount option can be used to prevent binaries 
#            from being executed out of /dev/shm. It can be dangerous to 
#            allow the execution of binaries from world-writable 
#            temporary storage directories such as /dev/shm. Add the 
#            noexec option to the fourth column of /etc/fstab for the 
#            line which controls mounting of /dev/shm.
#
#            Allowing users to execute binaries from world-writable 
#            directories such as /dev/shm can expose the system to 
#            potential compromise.
#
#################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Add 'noexec' to the '/dev/shm'"
diag_out "  filesystem's mount options."
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

