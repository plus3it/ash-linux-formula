# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38464
# Finding ID:	V-38464
# Version:	RHEL-06-000511
# Finding Level:	Medium
#
#     The audit system must take appropriate action when there are disk 
#     errors on the audit storage volume. Taking appropriate action in case 
#     of disk errors will minimize the possibility of losing audit records.
#
############################################################

script_V38464-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38464.sh

file_V38464:
  file.replace:
  - name: /etc/audit/auditd.conf
  - pattern: "^disk_error_action =.*"
  - repl: "disk_error_action = HALT"

