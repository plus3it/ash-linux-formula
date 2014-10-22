#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38599
# Finding ID:	V-38599
# Version:	RHEL-06-000348
# Finding Level:	Medium
#
#     The FTPS/FTP service on the system must be configured with the 
#     Department of Defense (DoD) login banner. This setting will cause the 
#     system greeting banner to be used for FTP connections as well.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38599"
diag_out "  Enable security warning-banners"
diag_out "  for FTP services"
diag_out "----------------------------------"
