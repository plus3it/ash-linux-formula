# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38468
# Finding ID:	V-38468
# Version:	RHEL-06-000510
# Finding Level:	Medium
#
#     The audit system must take appropriate action when the audit storage 
#     volume is full. Taking appropriate action in case of a filled audit 
#     storage volume will minimize the possibility of losing audit records.
#
#  CCI: CCI-000140
#  NIST SP 800-53 :: AU-5 b
#  NIST SP 800-53A :: AU-5.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-5 b
#
############################################################

script_V38468-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38468.sh

file_V38468:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: "^disk_full_action =.*"
    - repl: "disk_full_action = HALT"
