#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38698
# Finding ID:	V-38698
# Version:	
# Finding Level:	Medium
#
#     The operating system must employ automated mechanisms to detect the 
#     presence of unauthorized software on organizational information 
#     systems and notify designated organizational officials in accordance 
#     with the organization defined frequency. By default, AIDE does not 
#     install itself for periodic execution. Periodically running AIDE may 
#     reveal unexpected changes in installed files.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38698"
diag_out "  OS must be configured to detect"
diag_out "  additon of unauthorized"
diag_out "  software"
diag_out "----------------------------------"

