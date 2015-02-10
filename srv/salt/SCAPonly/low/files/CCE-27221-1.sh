#!/bin/sh
# This Salt test/lockdown implements a SCAP item that has not yet been 
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-27221-1
#
# Rule Summary: disable_prelink
#
# Rule Text: The prelinking feature changes binaries in an attempt to 
#            decrease their startup time. The prelinking feature can
#            interfere with the operation of AIDE, because it changes
#            binaries.
#
###########################################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "SCAP Recommendation: "
diag_out "  disable binary pre-linking "
diag_out "  feature to prevent interference"
diag_out "  with operation of AIDE"
diag_out "NOTE: Not yet accepted into STIGs"
diag_out "----------------------------------"
