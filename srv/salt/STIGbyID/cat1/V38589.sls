# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38589
# Finding ID:	V-38589
# Version:	RHEL-06-000211
# Finding Level:	High
#
#     The telnet daemon must not be running. The telnet protocol uses 
#     unencrypted network communication, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

script_V38589-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38589.sh

# (Need to rewrite once 2.7's fix to salt.states.service is available...)
cmd_V38589-disable:
  cmd.run:
  - name: 'chkconfig telnet off'
  - onlyif: 'chkconfig telnet --list | cut -f 2 | grep on'

