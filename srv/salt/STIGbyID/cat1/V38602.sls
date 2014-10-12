#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38602
# Finding ID:	V-38602
# Version:	RHEL-06-000218
# Finding Level:	High
#
#     The rlogind service must not be running. The rlogin service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

script_V38602-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38602.sh

# (Need to rewrite once 2.7's fix to salt.states.service is available...)
cmd_V38602-disable:
  cmd.run:
  - name: 'chkconfig rlogin off'
  - onlyif: 'chkconfig rlogin --list | cut -f 2 | grep on'

