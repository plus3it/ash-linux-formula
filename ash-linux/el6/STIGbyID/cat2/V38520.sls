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
#  CCI: CCI-001348
#  NIST SP 800-53 :: AU-9 (2)
#  NIST SP 800-53A :: AU-9 (2).1 (iii)
#  NIST SP 800-53 Revision 4 :: AU-9 (2)
#
############################################################

{%- set stigId = 'V38520' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

script_{{ stigId }}-helper:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: '/root'
