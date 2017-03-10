#!/bin/sh
# Finding URL:	https://www.tenable.com/plugins/index.php?view=single&id=71049
# Family:	Miscellaneous
# Nessus ID:	71049
# Bugtraq ID:	
# CVE ID:	
# Finding Level:	low
#
#     The SSH daemon must be configured to use only strong MAC
#     algorithms. Configured algorithms should not allow MD5
#     or 96-bit MAC algorithms.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: Nessus-71049"
diag_out "  SSH daemon must be configured to"
diag_out "  use only FIPS 140-2 approved"
diag_out "  MACs"
diag_out "----------------------------------"
