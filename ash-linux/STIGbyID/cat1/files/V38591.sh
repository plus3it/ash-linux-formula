#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38591
# Finding ID:	V-38591
# Version:	RHEL-06-000213
# Finding Level:	High
#
#     The rsh-server package must not be installed. The "rsh-server" 
#     package provides several obsolete and insecure network services. 
#     Removing it decreases the risk of those services' accidental (or 
#     intentional) activation.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38591"
diag_out "  The rsh-server package must not"
diag_out "  be installed"
diag_out "----------------------------------"

