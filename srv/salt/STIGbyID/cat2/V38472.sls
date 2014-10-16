#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38472
# Finding ID:	V-38472
# Version:	RHEL-06-000048
# Finding Level:	Medium
#
#     All system command files must be owned by root. System binaries are 
#     executed by privileged users as well as system services, and 
#     restrictive permissions are necessary to ensure that their execution 
#     of these programs cannot be co-opted.
#
############################################################

cript_V38472-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38472.sh

cmd_NotImplemented:
  cmd.run:
  - name: 'echo NOT IMPLEMENTED'

