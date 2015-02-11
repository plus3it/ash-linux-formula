#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38667
# Finding ID:	V-38667
# Version:	RHEL-06-000285
# Finding Level:	Medium
#
#     Adding host-based intrusion detection tools can provide the 
#     capability to automatically take actions in response to malicious 
#     behavior, which can provide additional agility in reacting to network 
#     threats. These tools also often include a reporting capability to 
#     provide network awareness of system, which may not otherwise exist in 
#     an organization's systems management regime. 
#
############################################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38667"
diag_out "  Verify that intrusion-detection"
diag_out "  tools are installed and active"
diag_out "----------------------------------"

