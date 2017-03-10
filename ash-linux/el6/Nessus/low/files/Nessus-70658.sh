#!/bin/sh
# Finding URL:	https://www.tenable.com/plugins/index.php?view=single&id=71049
# Family:	Miscellaneous
# Nessus ID:	70658
# Bugtraq ID:	
# CVE ID:	
# Finding Level:	low
#
#     The SSH daemon must be configured to disable weak
#     ciphers. Configured ciphers should not allow CBC mode.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: Nessus-70658"
diag_out "  SSH daemon must be configured to"
diag_out "  use only FIPS 140-2 approved"
diag_out "  ciphers"
diag_out "----------------------------------"
