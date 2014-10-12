# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38598
# Finding ID:	V-38598
# Version:	RHEL-06-000216
# Finding Level:	High
#
#     The rexecd service must not be running. The rexec service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen by ...
#
############################################################

script_V38598-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38598.sh

# (Need to rewrite once 2.7's fix to salt.states.service is available...)
cmd_V38598-disable:
  cmd.run:
  - name: 'chkconfig rexec off'
  - onlyif: 'chkconfig rexec --list | cut -f 2 | grep on'

