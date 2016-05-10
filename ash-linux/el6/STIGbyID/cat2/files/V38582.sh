#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38582
# Finding ID:	V-38582
# Version:	RHEL-06-000203
# Finding Level:	Medium
#
#     The xinetd service must be disabled if no network services utilizing 
#     it are enabled. The xinetd service provides a dedicated listener 
#     service for some programs, which is no longer necessary for 
#     commonly-used network services. Disabling it ensures that these 
#     uncommon services are not running, and also prevents attacks against
#     xinetd itself.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38582"
diag_out "  Disale xinetd unless its use is"
diag_out "  specifically required"
diag_out "----------------------------------"
