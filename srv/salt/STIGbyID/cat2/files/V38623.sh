#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38623
# Finding ID:	V-38623
# Version:	
# Finding Level:	Medium
#
#     All rsyslog-generated log files must have mode 0600 or less 
#     permissive. Log files can contain valuable information regarding 
#     system configuration. If the system log files are not protected, 
#     unauthorized users could change the logged data, eliminating their 
#     forensic value.
#
############################################################

