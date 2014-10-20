# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38498
# Finding ID:	V-38498
# Version:	RHEL-06-000383
# Finding Level:	Medium
#
#     Audit log files must have mode 0640 or less permissive. If users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
############################################################

script_V38498-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38498.sh

directory_V38498:
  file.directory:
  - name: /var/log/audit
  - file_mode: 0640
  - recurse:
    - mode

