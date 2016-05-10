#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38593
# Finding ID:	V-38593
# Version:	RHEL-06-000073
# Finding Level:	Medium
#
#     The Department of Defense (DoD) login banner must be displayed 
#     immediately prior to, or as part of, console login prompts. An 
#     appropriate warning message reinforces policy awareness during the 
#     logon process and facilitates possible legal action against attackers.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38593"
diag_out "  Security warning banners must be"
diag_out "  presented for all interactive"
diag_out "  login attempts"
diag_out "----------------------------------"
