#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38606
# Finding ID:	V-38606
# Version:	RHEL-06-000222
# Finding Level:	Medium
#
#     The tftp-server package must not be installed. Removing the 
#     "tftp-server" package decreases the risk of the accidental (or 
#     intentional) activation of tftp services.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38606"
diag_out "  The tftp-server package must not"
diag_out "  be installed"
diag_out "----------------------------------"
