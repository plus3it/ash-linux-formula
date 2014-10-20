#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38597
# Finding ID:	V-38597
# Version:	
# Finding Level:	Medium
#
#     The system must limit the ability of processes to have simultaneous 
#     write and execute access to memory. ExecShield uses the segmentation 
#     feature on all x86 systems to prevent execution in memory higher than 
#     a certain address. It writes an address as a limit in the code 
#     segment descriptor, to control ...
#
############################################################

