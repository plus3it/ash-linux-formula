# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38520
# Finding ID:	V-38520
# Version:	RHEL-06-000136
# Finding Level:	Medium
#
#     The operating system must back up audit records on an organization 
#     defined frequency onto a different system or media than the system 
#     being audited. A log server (loghost) receives syslog messages from 
#     one or more systems. This data can be used as an additional log 
#     source in the event a system is compromised and its local logs are 
#     suspect. ...
#
############################################################

script_V38520-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38520.sh

script_V38520-helper:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38520-helper.sh

