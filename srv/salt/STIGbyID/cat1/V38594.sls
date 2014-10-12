# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38594
# Finding ID:	V-38594
# Version:	RHEL-06-000214
# Finding Level:	High
#
#     The rshd service must not be running. The rsh service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen by ...
#
############################################################

script_V38594-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38594.sh

# (Need to rewrite once 2.7's fix to salt.states.service is available...)
cmd_V38594-disable:
  cmd.run:
  - name: 'chkconfig rsh off'
  - onlyif: 'chkconfig rsh --list | cut -f 2 | grep on'

