#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38676
# Finding ID:	V-38676
# Version:	RHEL-06-000291
# Finding Level:	Low
#
#     The xorg-x11-server-common (X Windows) package must not be installed, 
#     unless required. Unnecessary packages should not be installed to 
#     decrease the attack surface of the system.
#
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38676"
diag_out "  The xorg-x11-server-common (X"
diag_out "  Windows) package should not be"
diag_out "  installed"
diag_out "----------------------------------"
