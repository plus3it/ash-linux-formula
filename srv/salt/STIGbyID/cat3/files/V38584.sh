#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38584
# Finding ID:	V-38584
# Version:	RHEL-06-000204
# Finding Level:	Low
#
#     The xinetd service must be uninstalled if no network services 
#     utilizing it are enabled. Removing the "xinetd" package decreases the 
#     risk of the xinetd service's accidental (or intentional) activation.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38584"
diag_out "  xinetd service must be"
diag_out "  uninstalled if no network"
diag_out "  services utilizing it are"
diag_out "  enabled"
diag_out "----------------------------------"
