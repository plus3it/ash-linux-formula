#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38648
# Finding ID:	V-38648
# Version:	RHEL-06-000267
# Finding Level:	Low
#
#     The qpidd service must not be running. The qpidd service is 
#     automatically installed when the "base" package selection is selected 
#     during installation. The qpidd service listens for network 
#     connections which increases the attack surface of the system. If the 
#     system is not intended to receive AMQP traffic then the "qpidd" 
#     service is not needed and should be disabled or removed.
#
############################################################

diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "STIG Finding ID: V-38648"
diag_out "  The qpidd service must not be"
diag_out "  running."
diag_out "----------------------------------"
