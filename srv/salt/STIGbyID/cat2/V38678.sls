# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38678
# Finding ID:	V-38678
# Version:	RHEL-06-000311
# Finding Level:	Medium
#
#     The audit system must provide a warning when allocated audit record 
#     storage volume reaches a documented percentage of maximum audit 
#     record storage capacity. Notifying administrators of an impending 
#     disk space problem may allow them to take corrective action prior to 
#     any disruption.
#
############################################################

script_V38678-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38678.sh

cmd_V38678-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

