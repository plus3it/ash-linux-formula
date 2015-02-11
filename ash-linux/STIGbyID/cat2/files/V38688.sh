#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38688
# Finding ID:	V-38688
# Version:	RHEL-06-000324
# Finding Level:	Medium
#
#     A login banner must be displayed immediately prior to, or as part of, 
#     graphical desktop environment login prompts. An appropriate warning 
#     message reinforces policy awareness during the logon process and 
#     facilitates possible legal action against attackers.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38688"
diag_out "  display login banner as part of"
diag_out "  graphical desktop environment"
diag_out "  login prompts."
diag_out "----------------------------------"

