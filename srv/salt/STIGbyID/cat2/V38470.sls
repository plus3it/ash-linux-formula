# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38470
# Finding ID:	V-38470
# Version:	RHEL-06-000005
# Finding Level:	Medium
#
#     The audit system must alert designated staff members when the audit 
#     storage volume approaches capacity. Notifying administrators of an 
#     impending disk space problem may allow them to take corrective action 
#     prior to any disruption.
#
#  CCI: CCI-000138
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (ii)
#
############################################################

script_V38470-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38470.sh

file_V38470:
  file.replace:
  - name: /etc/audit/auditd.conf
  - pattern: "^space_left_action =.*"
  - repl: "space_left_action = email"

