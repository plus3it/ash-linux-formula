#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_fs_suid_dumpable
#
# Security identifiers:
# - CCE-27044-7
#
# Rule Summary: Disable core dumps for SUID programs
#
# Rule Text: The core dump of a setuid program is more likely to contain 
#            sensitive data, as the program itself runs with greater 
#            privileges than the user who initiated execution of the 
#            program. Disabling the ability for any setuid program to 
#            write a core file decreases the risk of unauthorized access 
#            of such data.
#
#################################################################


# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  Disable core dumps for SUID"
diag_out "  programs"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"

