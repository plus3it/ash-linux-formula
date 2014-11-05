#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38641
# Finding ID:	V-38641
# Version:	RHEL-06-000262
# Finding Level:	Low
#
#     The atd service must be disabled. The "atd" service could be used by 
#     an unsophisticated insider to carry out activities outside of a 
#     normal login session, which could complicate accountability. 
#     Furthermore, the need to schedule tasks with "at" or "batch" is not 
#     common. 
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38641"
diag_out "  The atd service must be"
diag_out "  disabled."
diag_out "----------------------------------"
